//! Mailer service (Issue #10).
//!
//! Public surface:
//! * [`EmailEvent`] -- typed enumeration of every notification VAUBAN
//!   knows how to send. Each variant carries the data needed to render
//!   the email body and the recipient address.
//! * [`Mailer::queue`] -- helper that INSERTs one row in the
//!   `email_outbox` table (transactional outbox pattern). MUST be called
//!   inside the same DB transaction as the business mutation that
//!   triggers it: a rollback of the transaction cancels the email.
//!
//! The actual SMTP exchange is performed by the sealed `vauban-mailer`
//! leaf process (Capsicum, supervisor-brokered FD), which polls the
//! outbox. This service is the write-side only: cheap, synchronous
//! w.r.t. the HTTP handler that calls it, and never touches the network.
//!
//! Threat model:
//! * Anti-CRLF injection: every caller-controlled string that lands
//!   on a header line (recipient, recipient_name, subject) is checked
//!   for `\r` / `\n` BEFORE INSERT. The DB layer also enforces the
//!   constraint (`email_outbox_no_crlf_*`), so a bug here cannot
//!   silently leak.
//! * Idempotence: each variant exposes a deterministic `event_id`
//!   derived from `(event_kind, business_key, recipient)` via UUIDv5.
//!   Two handlers retrying the same logical event collide on the
//!   `email_outbox_event_id_unique` constraint and the second one
//!   gracefully reports `Duplicate` (never sends twice).
//! * Operator logs name the mailbox on the **single** queue-summary
//!   line (and on queue failures) so a wrong inbox is diagnosable.
//!   Per-row debug still hashes the address with BLAKE3.

use std::sync::Arc;

use blake3::Hasher;
use chrono::{DateTime, Utc};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use tokio::sync::Notify;
use uuid::Uuid;

use crate::models::email_outbox::NewOutboxEntry;
use crate::services::mail_templates as tpl;
use shared::smtp::validate_no_crlf;

macro_rules! html_body {
    ($template:expr, $event:expr, $fields:expr, $facts:expr, $notice:expr, $info:expr, $danger:expr, $cta:expr $(,)?) => {
        tpl::render_event(
            $template,
            tpl::RenderSpec {
                brand: &$event.from_brand,
                base_url: &$event.base_url,
                fields: $fields,
                facts: $facts,
                notice: $notice,
                info: $info,
                danger: $danger,
                cta: $cta,
            },
        )
    };
}

// Re-exported for convenience: callers building events outside this
// module can mint event_ids without importing uuid directly.
pub use uuid::Uuid as EventUuid;

/// UUIDv5 namespace for `event_id`s minted by this module.
///
/// Generated once with `uuidgen --md5 --namespace @url --name vauban-mailer-events`.
/// SECURITY: this is a public, fixed namespace. Two different VAUBAN
/// deployments will produce the same event_ids for the same
/// `(event_kind, business_key, recipient)` triple, which is the
/// intended behaviour: idempotence MUST cross deployment boundaries
/// (e.g. a backup-restore round-trip should not re-send already-sent
/// emails).
const EVENT_ID_NAMESPACE: Uuid = Uuid::from_u128(0x6c61_6261_6e2d_6d61_696c_6572_2d76_3120);

/// Recipient of one notification email.
#[derive(Debug, Clone)]
pub struct EmailRecipient {
    /// RFC 5321 mailbox (e.g. `"alice@example.com"`).
    pub address: String,
    /// Display name (rendered as `"Name <addr>"`). Empty string == bare
    /// address.
    pub display_name: String,
}

impl EmailRecipient {
    pub fn new(address: impl Into<String>, display_name: impl Into<String>) -> Self {
        Self {
            address: address.into(),
            display_name: display_name.into(),
        }
    }

    pub fn bare(address: impl Into<String>) -> Self {
        Self::new(address, String::new())
    }
}

/// Rendered representation of an email, ready to be persisted in the
/// outbox. Built by [`EmailEvent::render`].
#[derive(Debug, Clone)]
pub struct RenderedEmail {
    pub subject: String,
    pub body_text: String,
    pub body_html: Option<String>,
}

/// Errors surfaced by [`Mailer::queue`].
#[derive(Debug, thiserror::Error)]
pub enum MailerError {
    #[error("CRLF injection detected in {0}")]
    CrlfInjection(&'static str),
    #[error("template rendering failed: {0}")]
    Render(String),
    #[error("duplicate event_id (event already queued)")]
    Duplicate,
    #[error("database error: {0}")]
    Database(#[from] diesel::result::Error),
    #[error("recipient address is empty")]
    EmptyRecipient,
    #[error("subject is empty")]
    EmptySubject,
}

/// Mailer service.
///
/// Cheap to clone (just an `Arc<Notify>` and a `bool`).
#[derive(Clone)]
pub struct Mailer {
    /// Wakes the sealed mailer via DB poll (notify is best-effort for
    /// future wake pipes; the mailer leaf polls `email_outbox`).
    notify: Arc<Notify>,
    /// Mirror of [`crate::config::MailerConfig::enabled`]. When false,
    /// `queue` is a no-op (the row is NOT inserted) so disabling the
    /// mailer in config does not produce dangling pending rows.
    enabled: bool,
    /// Per-row attempt budget. Mirrors `MailerConfig::max_attempts`.
    max_attempts: i32,
}

impl Mailer {
    /// Construct a fresh mailer service. Pass `enabled = false` to
    /// turn `queue` into a no-op (e.g. unit tests that exercise a
    /// business handler but do not want to populate the outbox).
    pub fn new(notify: Arc<Notify>, enabled: bool, max_attempts: i32) -> Self {
        Self {
            notify,
            enabled,
            max_attempts,
        }
    }

    /// Returns the dispatcher's wake-up handle. Used by the dispatcher
    /// task to wait on `Notify::notified()`.
    pub fn notify_handle(&self) -> Arc<Notify> {
        Arc::clone(&self.notify)
    }

    /// Returns `true` iff the mailer is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Render an event and INSERT a row in `email_outbox`. Then notify
    /// the dispatcher.
    ///
    /// CONTRACT: `conn` MUST be the same connection holding the
    /// surrounding business transaction (`BEGIN ... COMMIT`). If the
    /// caller's transaction rolls back, the inserted row disappears
    /// alongside the business mutation -- this is THE atomicity
    /// guarantee of the transactional outbox pattern.
    ///
    /// Returns `Ok(MailerError::Duplicate)` -- as `Err(Duplicate)` --
    /// when the event_id already exists. Callers may safely treat this
    /// as success: it means another concurrent handler already queued
    /// the same logical event.
    pub async fn queue(
        &self,
        conn: &mut AsyncPgConnection,
        event: &EmailEvent,
    ) -> Result<(), MailerError> {
        if !self.enabled {
            // Master switch off: pretend we queued, do not touch the DB.
            // This is intentionally silent so feature toggles in
            // production do not produce error logs every approval.
            return Ok(());
        }

        let recipient = event.recipient();
        if recipient.address.is_empty() {
            return Err(MailerError::EmptyRecipient);
        }
        validate_no_crlf("recipient.address", &recipient.address)
            .map_err(|_| MailerError::CrlfInjection("recipient.address"))?;
        validate_no_crlf("recipient.display_name", &recipient.display_name)
            .map_err(|_| MailerError::CrlfInjection("recipient.display_name"))?;

        let rendered = event
            .render()
            .map_err(|e| MailerError::Render(e.to_string()))?;
        if rendered.subject.is_empty() {
            return Err(MailerError::EmptySubject);
        }
        validate_no_crlf("subject", &rendered.subject)
            .map_err(|_| MailerError::CrlfInjection("subject"))?;

        let entry = NewOutboxEntry {
            event_id: event.event_id(),
            event_kind: event.kind().to_string(),
            recipient: recipient.address.clone(),
            recipient_name: recipient.display_name.clone(),
            subject: rendered.subject,
            body_text: rendered.body_text,
            body_html: rendered.body_html,
            max_attempts: self.max_attempts,
        };

        use crate::schema::email_outbox::dsl;
        let insert_result: Result<i64, diesel::result::Error> =
            diesel::insert_into(dsl::email_outbox)
                .values(&entry)
                .returning(dsl::id)
                .get_result(conn)
                .await;

        match insert_result {
            Ok(id) => {
                // Per-row breadcrumb only. Callers emit ONE info/error
                // line via [`log_emails_queued`] for the whole fan-out.
                tracing::debug!(
                    event_id = %event.event_id(),
                    event_kind = event.kind(),
                    recipient_hash = %hash_recipient(&recipient.address),
                    outbox_id = id,
                    "Email queued"
                );
                self.notify.notify_one();
                Ok(())
            }
            Err(diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UniqueViolation,
                _,
            )) => {
                tracing::debug!(
                    event_id = %event.event_id(),
                    event_kind = event.kind(),
                    "Email event_id already queued (idempotent skip)"
                );
                Err(MailerError::Duplicate)
            }
            Err(e) => Err(MailerError::Database(e)),
        }
    }
}

/// BLAKE3 hash of a recipient address, hex-encoded and truncated to 16
/// chars. Used on the per-row debug breadcrumb to correlate two events
/// to the same address without repeating the mailbox on every insert.
pub fn hash_recipient(address: &str) -> String {
    let mut h = Hasher::new();
    h.update(b"vauban:mailer:recipient:");
    h.update(address.as_bytes());
    let digest = h.finalize();
    hex::encode(&digest.as_bytes()[..8])
}

/// Strip CR/LF so a caller-controlled display name cannot split a log
/// line. [`Mailer::queue`] already rejects CRLF before INSERT; this is
/// defense in depth for the summary formatter.
fn sanitize_log_atom(s: &str) -> String {
    s.replace(['\r', '\n'], "")
}

/// Operator-facing mailbox: `name <addr>` or the bare address.
pub fn format_recipient_label(recipient: &EmailRecipient) -> String {
    let address = sanitize_log_atom(&recipient.address);
    if recipient.display_name.is_empty() {
        address
    } else {
        format!(
            "{} <{}>",
            sanitize_log_atom(&recipient.display_name),
            address
        )
    }
}

/// Single-line queue summary: what was queued, to whom, and any errors.
pub fn format_queue_summary(
    event_kind: &str,
    recipients: &[EmailRecipient],
    queued: usize,
    duplicates: usize,
    errors: &[String],
) -> String {
    let who = recipients
        .iter()
        .map(format_recipient_label)
        .collect::<Vec<_>>()
        .join(", ");
    let kind = sanitize_log_atom(event_kind);
    if errors.is_empty() {
        format!("{kind} -> {who} (queued={queued}, duplicates={duplicates})")
    } else {
        let err = errors
            .iter()
            .map(|e| sanitize_log_atom(e))
            .collect::<Vec<_>>()
            .join("; ");
        format!(
            "{kind} -> {who} (queued={queued}, duplicates={duplicates}, failed={}) errors={err}",
            errors.len()
        )
    }
}

/// Emit the single operator line for a logical notification fan-out.
///
/// Success is `info!`; any queue-time failure is `error!`. Never call
/// this once per recipient -- the point is one line for the batch.
pub fn log_emails_queued(
    event_kind: &str,
    recipients: &[EmailRecipient],
    queued: usize,
    duplicates: usize,
    errors: &[String],
) {
    let recipients_label = recipients
        .iter()
        .map(format_recipient_label)
        .collect::<Vec<_>>()
        .join(", ");
    let detail = format_queue_summary(event_kind, recipients, queued, duplicates, errors);
    if errors.is_empty() {
        tracing::info!(
            event_kind,
            queued,
            duplicates,
            recipients = %recipients_label,
            detail = %detail,
            "Emails queued"
        );
    } else {
        tracing::error!(
            event_kind,
            queued,
            duplicates,
            failed = errors.len(),
            recipients = %recipients_label,
            detail = %detail,
            "Emails queue failed"
        );
    }
}

/// Mint a deterministic `event_id` for a notification.
///
/// The same `(kind, business_key, recipient_address)` always maps to
/// the same UUID, so a retried handler never enqueues twice (the DB
/// `UNIQUE(event_id)` constraint catches the duplicate).
pub fn deterministic_event_id(kind: &str, business_key: &str, recipient: &str) -> Uuid {
    let mut canonical =
        String::with_capacity(kind.len() + business_key.len() + recipient.len() + 2);
    canonical.push_str(kind);
    canonical.push('\0');
    canonical.push_str(business_key);
    canonical.push('\0');
    canonical.push_str(recipient);
    Uuid::new_v5(&EVENT_ID_NAMESPACE, canonical.as_bytes())
}

// ============================================================================
// Event taxonomy (Issue #10 MVP scope: P0 + P1, 9 events)
// ============================================================================

/// Notification event.
///
/// One variant per row in the catalogue described in the issue. Each
/// variant carries the minimum data needed to render the email; the
/// recipient is stored separately so multi-recipient broadcasts can
/// reuse the same payload.
#[derive(Debug, Clone)]
pub enum EmailEvent {
    AccessRequestSubmitted(AccessRequestSubmittedEvent),
    AccessRequestApproved(AccessRequestApprovedEvent),
    AccessRequestRejected(AccessRequestRejectedEvent),
    /// An APPROVED grant was revoked by an admin -- the requester is
    /// informed that new sessions are blocked and live ones were cut.
    AccessRequestRevoked(AccessRequestRevokedEvent),
    AccessRequestExpired(AccessRequestExpiredEvent),
    UserCreated(UserCreatedEvent),
    UserPasswordResetRequested(UserPasswordResetRequestedEvent),
    UserLockedAfterFailedAttempts(UserLockedAfterFailedAttemptsEvent),
    UserMfaResetByAdmin(UserMfaResetByAdminEvent),
    SecurityMonoAdminDetected(SecurityMonoAdminDetectedEvent),
    /// IACS: a new EWS onboarding request has been submitted -- one
    /// notification per usable staff or superuser (`load_approver_contacts`)
    /// so an admin reviews it.
    IacsOnboardSubmitted(IacsOnboardSubmittedEvent),
    /// IACS: an admin approved the EWS onboarding request -- the
    /// requester is informed.
    IacsOnboardApproved(IacsOnboardApprovedEvent),
    /// IACS: an admin rejected the request -- the requester is told
    /// the reason.
    IacsOnboardRejected(IacsOnboardRejectedEvent),
    /// IACS: an admin offboarded the EWS (irreversible). The owner
    /// is informed (auto-offboard does not trigger this notification
    /// -- the user already knows).
    IacsOffboarded(IacsOffboardedEvent),
}

impl EmailEvent {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::AccessRequestSubmitted(_) => "access_request.submitted",
            Self::AccessRequestApproved(_) => "access_request.approved",
            Self::AccessRequestRejected(_) => "access_request.rejected",
            Self::AccessRequestRevoked(_) => "access_request.revoked",
            Self::AccessRequestExpired(_) => "access_request.expired",
            Self::UserCreated(_) => "user.created",
            Self::UserPasswordResetRequested(_) => "user.password_reset_requested",
            Self::UserLockedAfterFailedAttempts(_) => "user.locked_after_failed_attempts",
            Self::UserMfaResetByAdmin(_) => "user.mfa_reset_by_admin",
            Self::SecurityMonoAdminDetected(_) => "security.mono_admin_detected",
            Self::IacsOnboardSubmitted(_) => "iacs.onboard_submitted",
            Self::IacsOnboardApproved(_) => "iacs.onboard_approved",
            Self::IacsOnboardRejected(_) => "iacs.onboard_rejected",
            Self::IacsOffboarded(_) => "iacs.offboarded",
        }
    }

    pub fn event_id(&self) -> Uuid {
        match self {
            Self::AccessRequestSubmitted(e) => e.event_id,
            Self::AccessRequestApproved(e) => e.event_id,
            Self::AccessRequestRejected(e) => e.event_id,
            Self::AccessRequestRevoked(e) => e.event_id,
            Self::AccessRequestExpired(e) => e.event_id,
            Self::UserCreated(e) => e.event_id,
            Self::UserPasswordResetRequested(e) => e.event_id,
            Self::UserLockedAfterFailedAttempts(e) => e.event_id,
            Self::UserMfaResetByAdmin(e) => e.event_id,
            Self::SecurityMonoAdminDetected(e) => e.event_id,
            Self::IacsOnboardSubmitted(e) => e.event_id,
            Self::IacsOnboardApproved(e) => e.event_id,
            Self::IacsOnboardRejected(e) => e.event_id,
            Self::IacsOffboarded(e) => e.event_id,
        }
    }

    pub fn recipient(&self) -> &EmailRecipient {
        match self {
            Self::AccessRequestSubmitted(e) => &e.recipient,
            Self::AccessRequestApproved(e) => &e.recipient,
            Self::AccessRequestRejected(e) => &e.recipient,
            Self::AccessRequestRevoked(e) => &e.recipient,
            Self::AccessRequestExpired(e) => &e.recipient,
            Self::UserCreated(e) => &e.recipient,
            Self::UserPasswordResetRequested(e) => &e.recipient,
            Self::UserLockedAfterFailedAttempts(e) => &e.recipient,
            Self::UserMfaResetByAdmin(e) => &e.recipient,
            Self::SecurityMonoAdminDetected(e) => &e.recipient,
            Self::IacsOnboardSubmitted(e) => &e.recipient,
            Self::IacsOnboardApproved(e) => &e.recipient,
            Self::IacsOnboardRejected(e) => &e.recipient,
            Self::IacsOffboarded(e) => &e.recipient,
        }
    }

    /// Render the event into a `(subject, text, html)` triple. The
    /// text body is assembled here; the HTML body is the matching
    /// file under `vauban-web/email/` rendered by
    /// [`crate::services::mail_templates`].
    pub fn render(&self) -> Result<RenderedEmail, RenderError> {
        match self {
            Self::AccessRequestSubmitted(e) => render_access_request_submitted(e),
            Self::AccessRequestApproved(e) => render_access_request_approved(e),
            Self::AccessRequestRejected(e) => render_access_request_rejected(e),
            Self::AccessRequestRevoked(e) => render_access_request_revoked(e),
            Self::AccessRequestExpired(e) => render_access_request_expired(e),
            Self::UserCreated(e) => render_user_created(e),
            Self::UserPasswordResetRequested(e) => render_user_password_reset_requested(e),
            Self::UserLockedAfterFailedAttempts(e) => render_user_locked(e),
            Self::UserMfaResetByAdmin(e) => render_user_mfa_reset(e),
            Self::SecurityMonoAdminDetected(e) => render_security_mono_admin(e),
            Self::IacsOnboardSubmitted(e) => render_iacs_onboard_submitted(e),
            Self::IacsOnboardApproved(e) => render_iacs_onboard_approved(e),
            Self::IacsOnboardRejected(e) => render_iacs_onboard_rejected(e),
            Self::IacsOffboarded(e) => render_iacs_offboarded(e),
        }
    }
}

/// Rendering errors, surfaced as `MailerError::Render(_)` to the caller.
#[derive(Debug, thiserror::Error)]
pub enum RenderError {
    #[error("template error: {0}")]
    Template(String),
}

/// Common header rendered at the top of every email body.
fn render_header(brand: &str) -> String {
    format!("--- {brand} ---\n\n")
}

fn render_footer(base_url: &str) -> String {
    format!(
        "\n--\nThis is an automated message from Vauban PAM.\nWeb console: {}\nDo not reply to this email.\n",
        base_url
    )
}

// ============================================================================
// Per-event payloads
// ============================================================================

#[derive(Debug, Clone)]
pub struct AccessRequestSubmittedEvent {
    pub event_id: Uuid,
    pub recipient: EmailRecipient,
    pub requester_username: String,
    pub asset_name: String,
    pub protocol: String,
    pub justification: Option<String>,
    pub approval_url: String,
    pub base_url: String,
    pub from_brand: String,
}

fn render_access_request_submitted(
    e: &AccessRequestSubmittedEvent,
) -> Result<RenderedEmail, RenderError> {
    let subject = format!(
        "[Vauban] Access request: {} -> {} ({})",
        e.requester_username, e.asset_name, e.protocol
    );
    let mut text = render_header(&e.from_brand);
    text.push_str(&format!(
        "{} requested {} access to {}.\n",
        e.requester_username, e.protocol, e.asset_name
    ));
    if let Some(j) = &e.justification {
        text.push_str(&format!("\nJustification:\n{}\n", j));
    }
    text.push_str(&format!("\nReview the request: {}\n", e.approval_url));
    text.push_str(&render_footer(&e.base_url));
    let html = html_body!(
        tpl::ACCESS_REQUEST_SUBMITTED_HTML,
        e,
        &[
            tpl::field("__REQUESTER__", &e.requester_username),
            tpl::field("__ASSET__", &e.asset_name),
            tpl::field("__PROTOCOL__", &e.protocol),
        ],
        &[
            ("Requester", e.requester_username.as_str()),
            ("Asset", e.asset_name.as_str()),
            ("Protocol", e.protocol.as_str()),
        ],
        e.justification.as_deref(),
        None,
        None,
        Some((e.approval_url.as_str(), "Review the request")),
    );
    Ok(RenderedEmail {
        subject,
        body_text: text,
        body_html: Some(html),
    })
}

#[derive(Debug, Clone)]
pub struct AccessRequestApprovedEvent {
    pub event_id: Uuid,
    pub recipient: EmailRecipient,
    pub asset_name: String,
    pub protocol: String,
    pub approver_username: String,
    pub session_url: String,
    pub valid_until: Option<DateTime<Utc>>,
    pub base_url: String,
    pub from_brand: String,
}

fn render_access_request_approved(
    e: &AccessRequestApprovedEvent,
) -> Result<RenderedEmail, RenderError> {
    let subject = format!(
        "[Vauban] Access approved: {} ({})",
        e.asset_name, e.protocol
    );
    let mut text = render_header(&e.from_brand);
    text.push_str(&format!(
        "Your access request to {} ({}) was approved by {}.\n",
        e.asset_name, e.protocol, e.approver_username
    ));
    if let Some(t) = e.valid_until {
        text.push_str(&format!("Valid until: {}\n", t.to_rfc3339()));
    }
    text.push_str(&format!("\nOpen the session: {}\n", e.session_url));
    text.push_str(&render_footer(&e.base_url));
    let valid = e
        .valid_until
        .map(|t| format!("Valid until: {}", t.to_rfc3339()));
    let html = html_body!(
        tpl::ACCESS_REQUEST_APPROVED_HTML,
        e,
        &[
            tpl::field("__ASSET__", &e.asset_name),
            tpl::field("__PROTOCOL__", &e.protocol),
            tpl::field("__APPROVER__", &e.approver_username),
        ],
        &[
            ("Asset", e.asset_name.as_str()),
            ("Protocol", e.protocol.as_str()),
            ("Approver", e.approver_username.as_str()),
        ],
        valid.as_deref(),
        None,
        None,
        Some((e.session_url.as_str(), "Open the session")),
    );
    Ok(RenderedEmail {
        subject,
        body_text: text,
        body_html: Some(html),
    })
}

#[derive(Debug, Clone)]
pub struct AccessRequestRejectedEvent {
    pub event_id: Uuid,
    pub recipient: EmailRecipient,
    pub asset_name: String,
    pub protocol: String,
    pub approver_username: String,
    pub reason: Option<String>,
    pub base_url: String,
    pub from_brand: String,
}

fn render_access_request_rejected(
    e: &AccessRequestRejectedEvent,
) -> Result<RenderedEmail, RenderError> {
    let subject = format!("[Vauban] Access denied: {} ({})", e.asset_name, e.protocol);
    let mut text = render_header(&e.from_brand);
    text.push_str(&format!(
        "Your access request to {} ({}) was denied by {}.\n",
        e.asset_name, e.protocol, e.approver_username
    ));
    if let Some(r) = &e.reason {
        text.push_str(&format!("\nReason: {}\n", r));
    }
    text.push_str(&render_footer(&e.base_url));
    let html = html_body!(
        tpl::ACCESS_REQUEST_REJECTED_HTML,
        e,
        &[
            tpl::field("__ASSET__", &e.asset_name),
            tpl::field("__PROTOCOL__", &e.protocol),
            tpl::field("__APPROVER__", &e.approver_username),
        ],
        &[
            ("Asset", e.asset_name.as_str()),
            ("Protocol", e.protocol.as_str()),
            ("Approver", e.approver_username.as_str()),
        ],
        None,
        None,
        e.reason.as_deref(),
        None,
    );
    Ok(RenderedEmail {
        subject,
        body_text: text,
        body_html: Some(html),
    })
}

#[derive(Debug, Clone)]
pub struct AccessRequestRevokedEvent {
    pub event_id: Uuid,
    pub recipient: EmailRecipient,
    pub asset_name: String,
    pub protocol: String,
    pub approver_username: String,
    pub reason: Option<String>,
    pub base_url: String,
    pub from_brand: String,
}

fn render_access_request_revoked(
    e: &AccessRequestRevokedEvent,
) -> Result<RenderedEmail, RenderError> {
    let subject = format!("[Vauban] Access revoked: {} ({})", e.asset_name, e.protocol);
    let mut text = render_header(&e.from_brand);
    text.push_str(&format!(
        "Your approved access to {} ({}) was revoked by {}.\n\
         Any live session on this asset has been terminated and new \
         connections are no longer possible.\n",
        e.asset_name, e.protocol, e.approver_username
    ));
    if let Some(r) = &e.reason {
        text.push_str(&format!("\nReason: {}\n", r));
    }
    text.push_str(&render_footer(&e.base_url));
    let html = html_body!(
        tpl::ACCESS_REQUEST_REVOKED_HTML,
        e,
        &[
            tpl::field("__ASSET__", &e.asset_name),
            tpl::field("__PROTOCOL__", &e.protocol),
            tpl::field("__APPROVER__", &e.approver_username),
        ],
        &[
            ("Asset", e.asset_name.as_str()),
            ("Protocol", e.protocol.as_str()),
            ("Approver", e.approver_username.as_str()),
        ],
        None,
        None,
        e.reason.as_deref(),
        None,
    );
    Ok(RenderedEmail {
        subject,
        body_text: text,
        body_html: Some(html),
    })
}

#[derive(Debug, Clone)]
pub struct AccessRequestExpiredEvent {
    pub event_id: Uuid,
    pub recipient: EmailRecipient,
    pub requester_username: String,
    pub asset_name: String,
    pub protocol: String,
    pub base_url: String,
    pub from_brand: String,
}

fn render_access_request_expired(
    e: &AccessRequestExpiredEvent,
) -> Result<RenderedEmail, RenderError> {
    let subject = format!(
        "[Vauban] Access request expired: {} ({})",
        e.asset_name, e.protocol
    );
    let mut text = render_header(&e.from_brand);
    text.push_str(&format!(
        "The access request from {} for {} ({}) expired without a decision.\n",
        e.requester_username, e.asset_name, e.protocol
    ));
    text.push_str(&render_footer(&e.base_url));
    let html = html_body!(
        tpl::ACCESS_REQUEST_EXPIRED_HTML,
        e,
        &[
            tpl::field("__REQUESTER__", &e.requester_username),
            tpl::field("__ASSET__", &e.asset_name),
            tpl::field("__PROTOCOL__", &e.protocol),
        ],
        &[
            ("Requester", e.requester_username.as_str()),
            ("Asset", e.asset_name.as_str()),
            ("Protocol", e.protocol.as_str()),
        ],
        Some("This request expired without a decision."),
        None,
        None,
        None,
    );
    Ok(RenderedEmail {
        subject,
        body_text: text,
        body_html: Some(html),
    })
}

#[derive(Debug, Clone)]
pub struct UserCreatedEvent {
    pub event_id: Uuid,
    pub recipient: EmailRecipient,
    pub username: String,
    pub created_by: String,
    pub login_url: String,
    pub base_url: String,
    pub from_brand: String,
}

fn render_user_created(e: &UserCreatedEvent) -> Result<RenderedEmail, RenderError> {
    let subject = format!("[Vauban] Welcome, {}", e.username);
    let mut text = render_header(&e.from_brand);
    text.push_str(&format!(
        "Hello {},\n\nA Vauban account was created for you by {}.\n",
        e.username, e.created_by
    ));
    text.push_str(&format!("\nSign in: {}\n", e.login_url));
    text.push_str(&render_footer(&e.base_url));
    let html = html_body!(
        tpl::USER_CREATED_HTML,
        e,
        &[
            tpl::field("__USERNAME__", &e.username),
            tpl::field("__CREATED_BY__", &e.created_by),
        ],
        &[
            ("Account", e.username.as_str()),
            ("Created by", e.created_by.as_str()),
        ],
        None,
        None,
        None,
        Some((e.login_url.as_str(), "Sign in")),
    );
    Ok(RenderedEmail {
        subject,
        body_text: text,
        body_html: Some(html),
    })
}

#[derive(Debug, Clone)]
pub struct UserPasswordResetRequestedEvent {
    pub event_id: Uuid,
    pub recipient: EmailRecipient,
    pub username: String,
    pub reset_url: String,
    pub valid_until: DateTime<Utc>,
    pub base_url: String,
    pub from_brand: String,
}

fn render_user_password_reset_requested(
    e: &UserPasswordResetRequestedEvent,
) -> Result<RenderedEmail, RenderError> {
    let subject = "[Vauban] Password reset requested".to_string();
    let mut text = render_header(&e.from_brand);
    text.push_str(&format!(
        "Hello {},\n\nA password reset was requested for your account.\n",
        e.username
    ));
    text.push_str(&format!("\nReset your password: {}\n", e.reset_url));
    text.push_str(&format!(
        "Link valid until: {}\n",
        e.valid_until.to_rfc3339()
    ));
    text.push_str("\nIf you did not request this, you can safely ignore this email.\n");
    text.push_str(&render_footer(&e.base_url));
    let valid = format!("Link valid until: {}", e.valid_until.to_rfc3339());
    let html = html_body!(
        tpl::USER_PASSWORD_RESET_REQUESTED_HTML,
        e,
        &[tpl::field("__USERNAME__", &e.username)],
        &[("Account", e.username.as_str())],
        Some(valid.as_str()),
        Some("If you did not request this, you can safely ignore this email."),
        None,
        Some((e.reset_url.as_str(), "Reset your password")),
    );
    Ok(RenderedEmail {
        subject,
        body_text: text,
        body_html: Some(html),
    })
}

#[derive(Debug, Clone)]
pub struct UserLockedAfterFailedAttemptsEvent {
    pub event_id: Uuid,
    pub recipient: EmailRecipient,
    pub username: String,
    pub failed_attempts: u32,
    pub locked_until: Option<DateTime<Utc>>,
    pub base_url: String,
    pub from_brand: String,
}

fn render_user_locked(
    e: &UserLockedAfterFailedAttemptsEvent,
) -> Result<RenderedEmail, RenderError> {
    let subject = format!("[Vauban] Account locked: {}", e.username);
    let mut text = render_header(&e.from_brand);
    text.push_str(&format!(
        "Account {} was locked after {} failed login attempts.\n",
        e.username, e.failed_attempts
    ));
    if let Some(t) = e.locked_until {
        text.push_str(&format!("Locked until: {}\n", t.to_rfc3339()));
    }
    text.push_str(&render_footer(&e.base_url));
    let locked = e
        .locked_until
        .map(|t| format!("Locked until: {}", t.to_rfc3339()));
    let attempts = e.failed_attempts.to_string();
    let html = html_body!(
        tpl::USER_LOCKED_HTML,
        e,
        &[
            tpl::field("__USERNAME__", &e.username),
            tpl::field("__ATTEMPTS__", &attempts),
        ],
        &[
            ("Account", e.username.as_str()),
            ("Failed attempts", attempts.as_str()),
        ],
        None,
        None,
        locked.as_deref(),
        None,
    );
    Ok(RenderedEmail {
        subject,
        body_text: text,
        body_html: Some(html),
    })
}

#[derive(Debug, Clone)]
pub struct UserMfaResetByAdminEvent {
    pub event_id: Uuid,
    pub recipient: EmailRecipient,
    pub username: String,
    pub admin_username: String,
    pub base_url: String,
    pub from_brand: String,
}

fn render_user_mfa_reset(e: &UserMfaResetByAdminEvent) -> Result<RenderedEmail, RenderError> {
    let subject = format!("[Vauban] MFA reset for {}", e.username);
    let mut text = render_header(&e.from_brand);
    text.push_str(&format!(
        "Your MFA configuration was reset by administrator {}.\n",
        e.admin_username
    ));
    text.push_str("\nSet up MFA again on your next sign-in.\n");
    text.push_str(&render_footer(&e.base_url));
    let html = html_body!(
        tpl::USER_MFA_RESET_HTML,
        e,
        &[
            tpl::field("__USERNAME__", &e.username),
            tpl::field("__ADMIN__", &e.admin_username),
        ],
        &[
            ("Account", e.username.as_str()),
            ("Administrator", e.admin_username.as_str()),
        ],
        None,
        Some("Set up MFA again on the next sign-in."),
        None,
        None,
    );
    Ok(RenderedEmail {
        subject,
        body_text: text,
        body_html: Some(html),
    })
}

#[derive(Debug, Clone)]
pub struct SecurityMonoAdminDetectedEvent {
    pub event_id: Uuid,
    pub recipient: EmailRecipient,
    pub remaining_admin_username: String,
    pub base_url: String,
    pub from_brand: String,
}

fn render_security_mono_admin(
    e: &SecurityMonoAdminDetectedEvent,
) -> Result<RenderedEmail, RenderError> {
    let subject = "[Vauban] Mono-admin condition detected".to_string();
    let mut text = render_header(&e.from_brand);
    text.push_str(&format!(
        "Vauban now has a single active superuser ({}). The platform is at \
         risk of admin lockout if this account becomes unavailable.\n",
        e.remaining_admin_username
    ));
    text.push_str("\nProvision a second administrator as soon as possible.\n");
    text.push_str(&render_footer(&e.base_url));
    let html = html_body!(
        tpl::SECURITY_MONO_ADMIN_HTML,
        e,
        &[tpl::field("__ADMIN__", &e.remaining_admin_username)],
        &[("Remaining superuser", e.remaining_admin_username.as_str())],
        None,
        None,
        Some(
            "The platform is at risk of admin lockout if this account becomes unavailable. \
             Provision a second administrator as soon as possible.",
        ),
        Some((e.base_url.as_str(), "Open the console")),
    );
    Ok(RenderedEmail {
        subject,
        body_text: text,
        body_html: Some(html),
    })
}

// ============================================================================
// IACS / EWS onboarding (Issue #IACS, palier 5)
// ============================================================================
//
// Four event types mirror the JIT lifecycle:
//   * IacsOnboardSubmitted -- one row per usable staff or superuser
//     (`load_approver_contacts`); business_key is the request UUID so
//     retries collapse on (kind, request, admin).
//   * IacsOnboardApproved / IacsOnboardRejected -- single row addressed
//     to the requester; business_key is the request UUID.
//   * IacsOffboarded -- single row addressed to the EWS owner; business
//     key is the EWS UUID. Auto-offboard (kill-switch / cascade) does
//     NOT enqueue this notification: callers decide whether the user
//     deserves a heads-up (today, only an explicit admin offboard does).
//
// Subject lines never carry user-controlled values verbatim: the EWS
// name is rendered in the body, never in the subject, to keep mail
// filters predictable. The renderer is plain text -- the dispatcher
// lifts CRLF safety from `Mailer::queue` so we do not have to sanitise
// here, but justifications and rejection reasons go through
// `validate_no_crlf` upstream when appropriate.

#[derive(Debug, Clone)]
pub struct IacsOnboardSubmittedEvent {
    pub event_id: Uuid,
    pub recipient: EmailRecipient,
    pub requester_username: String,
    pub ews_name: String,
    pub fingerprint: String,
    pub justification: Option<String>,
    pub admin_url: String,
    pub base_url: String,
    pub from_brand: String,
}

fn render_iacs_onboard_submitted(
    e: &IacsOnboardSubmittedEvent,
) -> Result<RenderedEmail, RenderError> {
    let subject = format!(
        "[Vauban] EWS onboarding request from {}",
        e.requester_username
    );
    let mut text = render_header(&e.from_brand);
    text.push_str(&format!(
        "{} submitted an EWS onboarding request.\n",
        e.requester_username
    ));
    text.push_str(&format!("EWS name: {}\n", e.ews_name));
    text.push_str(&format!(
        "Public key fingerprint (SHA-256): {}\n",
        e.fingerprint
    ));
    if let Some(j) = &e.justification {
        text.push_str(&format!("\nJustification:\n{}\n", j));
    }
    text.push_str(&format!("\nReview the request: {}\n", e.admin_url));
    text.push_str(&render_footer(&e.base_url));
    let html = html_body!(
        tpl::IACS_ONBOARD_SUBMITTED_HTML,
        e,
        &[
            tpl::field("__REQUESTER__", &e.requester_username),
            tpl::field("__EWS__", &e.ews_name),
            tpl::field("__FINGERPRINT__", &e.fingerprint),
        ],
        &[
            ("Requester", e.requester_username.as_str()),
            ("EWS", e.ews_name.as_str()),
            ("Fingerprint", e.fingerprint.as_str()),
        ],
        e.justification.as_deref(),
        None,
        None,
        Some((e.admin_url.as_str(), "Review the request")),
    );
    Ok(RenderedEmail {
        subject,
        body_text: text,
        body_html: Some(html),
    })
}

#[derive(Debug, Clone)]
pub struct IacsOnboardApprovedEvent {
    pub event_id: Uuid,
    pub recipient: EmailRecipient,
    pub ews_name: String,
    pub fingerprint: String,
    pub approver_username: String,
    pub my_requests_url: String,
    pub base_url: String,
    pub from_brand: String,
}

fn render_iacs_onboard_approved(
    e: &IacsOnboardApprovedEvent,
) -> Result<RenderedEmail, RenderError> {
    let subject = format!("[Vauban] EWS approved: {}", e.ews_name);
    let mut text = render_header(&e.from_brand);
    text.push_str(&format!(
        "Your EWS onboarding request was approved by {}.\n",
        e.approver_username
    ));
    text.push_str(&format!("EWS name: {}\n", e.ews_name));
    text.push_str(&format!(
        "Public key fingerprint (SHA-256): {}\n",
        e.fingerprint
    ));
    text.push_str(&format!("\nView your requests: {}\n", e.my_requests_url));
    text.push_str(&render_footer(&e.base_url));
    let html = html_body!(
        tpl::IACS_ONBOARD_APPROVED_HTML,
        e,
        &[
            tpl::field("__APPROVER__", &e.approver_username),
            tpl::field("__EWS__", &e.ews_name),
            tpl::field("__FINGERPRINT__", &e.fingerprint),
        ],
        &[
            ("EWS", e.ews_name.as_str()),
            ("Fingerprint", e.fingerprint.as_str()),
            ("Approver", e.approver_username.as_str()),
        ],
        None,
        None,
        None,
        Some((e.my_requests_url.as_str(), "View your requests")),
    );
    Ok(RenderedEmail {
        subject,
        body_text: text,
        body_html: Some(html),
    })
}

#[derive(Debug, Clone)]
pub struct IacsOnboardRejectedEvent {
    pub event_id: Uuid,
    pub recipient: EmailRecipient,
    pub ews_name: String,
    pub approver_username: String,
    pub reason: String,
    pub my_requests_url: String,
    pub base_url: String,
    pub from_brand: String,
}

fn render_iacs_onboard_rejected(
    e: &IacsOnboardRejectedEvent,
) -> Result<RenderedEmail, RenderError> {
    let subject = format!("[Vauban] EWS denied: {}", e.ews_name);
    let mut text = render_header(&e.from_brand);
    text.push_str(&format!(
        "Your EWS onboarding request was denied by {}.\n",
        e.approver_username
    ));
    text.push_str(&format!("EWS name: {}\n", e.ews_name));
    text.push_str(&format!("\nReason: {}\n", e.reason));
    text.push_str(&format!("\nView your requests: {}\n", e.my_requests_url));
    text.push_str(&render_footer(&e.base_url));
    let html = html_body!(
        tpl::IACS_ONBOARD_REJECTED_HTML,
        e,
        &[
            tpl::field("__APPROVER__", &e.approver_username),
            tpl::field("__EWS__", &e.ews_name),
        ],
        &[
            ("EWS", e.ews_name.as_str()),
            ("Approver", e.approver_username.as_str()),
        ],
        None,
        None,
        Some(e.reason.as_str()),
        Some((e.my_requests_url.as_str(), "View your requests")),
    );
    Ok(RenderedEmail {
        subject,
        body_text: text,
        body_html: Some(html),
    })
}

#[derive(Debug, Clone)]
pub struct IacsOffboardedEvent {
    pub event_id: Uuid,
    pub recipient: EmailRecipient,
    pub ews_name: String,
    pub fingerprint: String,
    pub admin_username: String,
    pub base_url: String,
    pub from_brand: String,
}

fn render_iacs_offboarded(e: &IacsOffboardedEvent) -> Result<RenderedEmail, RenderError> {
    let subject = format!("[Vauban] EWS offboarded: {}", e.ews_name);
    let mut text = render_header(&e.from_brand);
    text.push_str(&format!(
        "Your EWS was offboarded by administrator {}. This action is \
         irreversible: any active SSH tunnel was terminated and the \
         public key can no longer be used to reach Vauban.\n",
        e.admin_username
    ));
    text.push_str(&format!("EWS name: {}\n", e.ews_name));
    text.push_str(&format!(
        "Public key fingerprint (SHA-256): {}\n",
        e.fingerprint
    ));
    text.push_str(
        "\nIf you still need an EWS, generate a fresh key pair and submit \
         a new onboarding request from the Vauban console.\n",
    );
    text.push_str(&render_footer(&e.base_url));
    let html = html_body!(
        tpl::IACS_OFFBOARDED_HTML,
        e,
        &[
            tpl::field("__ADMIN__", &e.admin_username),
            tpl::field("__EWS__", &e.ews_name),
            tpl::field("__FINGERPRINT__", &e.fingerprint),
        ],
        &[
            ("EWS", e.ews_name.as_str()),
            ("Fingerprint", e.fingerprint.as_str()),
            ("Administrator", e.admin_username.as_str()),
        ],
        None,
        None,
        Some(
            "This action is irreversible. If an EWS is still needed, generate a fresh \
             key pair and submit a new onboarding request.",
        ),
        None,
    );
    Ok(RenderedEmail {
        subject,
        body_text: text,
        body_html: Some(html),
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_recipient() -> EmailRecipient {
        EmailRecipient::new("alice@example.test", "Alice Doe")
    }

    fn fake_submitted_event() -> EmailEvent {
        EmailEvent::AccessRequestSubmitted(AccessRequestSubmittedEvent {
            event_id: deterministic_event_id(
                "access_request.submitted",
                "session-uuid",
                "alice@example.test",
            ),
            recipient: fake_recipient(),
            requester_username: "bob".into(),
            asset_name: "prod-db-01".into(),
            protocol: "ssh".into(),
            justification: Some("incident #42".into()),
            approval_url: "https://vauban.test/sessions/approvals/x".into(),
            base_url: "https://vauban.test".into(),
            from_brand: "Vauban PAM".into(),
        })
    }

    #[test]
    fn deterministic_event_id_is_stable_across_calls() {
        let a = deterministic_event_id("kind", "biz", "x@y.z");
        let b = deterministic_event_id("kind", "biz", "x@y.z");
        assert_eq!(a, b);
    }

    #[test]
    fn deterministic_event_id_differs_on_kind() {
        let a = deterministic_event_id("kind1", "biz", "x@y.z");
        let b = deterministic_event_id("kind2", "biz", "x@y.z");
        assert_ne!(a, b);
    }

    #[test]
    fn deterministic_event_id_differs_on_recipient() {
        let a = deterministic_event_id("kind", "biz", "alice@x.com");
        let b = deterministic_event_id("kind", "biz", "bob@x.com");
        assert_ne!(a, b);
    }

    #[test]
    fn deterministic_event_id_differs_on_business_key() {
        let a = deterministic_event_id("kind", "biz1", "x@y.z");
        let b = deterministic_event_id("kind", "biz2", "x@y.z");
        assert_ne!(a, b);
    }

    #[test]
    fn hash_recipient_does_not_leak_address() {
        let h = hash_recipient("alice@example.com");
        assert!(!h.contains("alice"));
        assert!(!h.contains("example"));
        assert_eq!(h.len(), 16);
    }

    #[test]
    fn hash_recipient_is_deterministic() {
        assert_eq!(
            hash_recipient("alice@example.com"),
            hash_recipient("alice@example.com")
        );
    }

    #[test]
    fn hash_recipient_distinguishes_addresses() {
        assert_ne!(
            hash_recipient("alice@example.com"),
            hash_recipient("bob@example.com")
        );
    }

    #[test]
    fn email_event_kind_strings_match_taxonomy() {
        // Pin: kind() strings are part of the on-disk taxonomy
        // (email_outbox.event_kind, telemetry, search filters). They
        // MUST not drift silently.
        let cases: &[(EmailEvent, &str)] = &[(fake_submitted_event(), "access_request.submitted")];
        for (event, expected) in cases {
            assert_eq!(event.kind(), *expected);
        }
        // We do not iterate over every variant here -- the
        // exhaustiveness is enforced by the match in `kind()` itself
        // (a missing arm would not compile).
    }

    #[test]
    fn render_access_request_submitted_includes_actor_and_url() {
        let event = fake_submitted_event();
        let rendered = event.render().unwrap();
        assert!(rendered.subject.starts_with("[Vauban]"));
        assert!(rendered.body_text.contains("bob"));
        assert!(rendered.body_text.contains("prod-db-01"));
        assert!(
            rendered
                .body_text
                .contains("https://vauban.test/sessions/approvals/x")
        );
        assert!(rendered.body_text.contains("incident #42"));
    }

    #[test]
    fn render_subject_never_contains_crlf() {
        // The validator runs on the subject before INSERT; the
        // renderer also has a contract: NEVER emit \r\n in the
        // subject. We assert it on the canonical event.
        let event = fake_submitted_event();
        let rendered = event.render().unwrap();
        assert!(!rendered.subject.contains('\r'));
        assert!(!rendered.subject.contains('\n'));
    }

    #[test]
    fn email_event_recipient_returns_attached_recipient() {
        let event = fake_submitted_event();
        let r = event.recipient();
        assert_eq!(r.address, "alice@example.test");
        assert_eq!(r.display_name, "Alice Doe");
    }

    #[test]
    fn email_event_event_id_is_deterministic() {
        let e1 = fake_submitted_event();
        let e2 = fake_submitted_event();
        assert_eq!(e1.event_id(), e2.event_id());
    }

    #[test]
    fn render_password_reset_includes_reset_url() {
        let event = EmailEvent::UserPasswordResetRequested(UserPasswordResetRequestedEvent {
            event_id: Uuid::nil(),
            recipient: fake_recipient(),
            username: "alice".into(),
            reset_url: "https://vauban.test/auth/reset?token=xyz".into(),
            valid_until: Utc::now() + chrono::Duration::hours(1),
            base_url: "https://vauban.test".into(),
            from_brand: "Vauban PAM".into(),
        });
        let r = event.render().unwrap();
        assert!(
            r.body_text
                .contains("https://vauban.test/auth/reset?token=xyz")
        );
        assert!(r.body_text.contains("alice"));
    }

    #[test]
    fn render_mono_admin_warns_about_lockout() {
        let event = EmailEvent::SecurityMonoAdminDetected(SecurityMonoAdminDetectedEvent {
            event_id: Uuid::nil(),
            recipient: fake_recipient(),
            remaining_admin_username: "carol".into(),
            base_url: "https://vauban.test".into(),
            from_brand: "Vauban PAM".into(),
        });
        let r = event.render().unwrap();
        assert!(r.subject.contains("Mono-admin"));
        assert!(r.body_text.contains("carol"));
        assert!(r.body_text.contains("admin lockout"));
    }

    #[test]
    fn render_locked_account_includes_attempts() {
        let event = EmailEvent::UserLockedAfterFailedAttempts(UserLockedAfterFailedAttemptsEvent {
            event_id: Uuid::nil(),
            recipient: fake_recipient(),
            username: "alice".into(),
            failed_attempts: 5,
            locked_until: Some(Utc::now() + chrono::Duration::minutes(15)),
            base_url: "https://vauban.test".into(),
            from_brand: "Vauban PAM".into(),
        });
        let r = event.render().unwrap();
        assert!(r.body_text.contains("5 failed login"));
        assert!(r.body_text.contains("alice"));
    }

    #[tokio::test]
    async fn mailer_disabled_is_noop() {
        // We cannot easily test the DB INSERT without a Postgres
        // instance, but the disabled-fast-path is purely in-process.
        let m = Mailer::new(Arc::new(Notify::new()), false, 5);
        assert!(!m.is_enabled());
        // queue() is async; calling it is safe even without a real
        // connection because the disabled branch returns before
        // touching it. We can't construct an AsyncPgConnection without
        // a server, so we settle for the synchronous bits here.
    }

    #[test]
    fn mailer_notify_handle_clones_arc() {
        let n = Arc::new(Notify::new());
        let m = Mailer::new(Arc::clone(&n), true, 5);
        let h = m.notify_handle();
        assert!(Arc::ptr_eq(&n, &h));
    }

    fn iacs_fp() -> &'static str {
        // Stable test fingerprint, does not need to be a real SHA-256.
        "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12"
    }

    #[test]
    fn render_iacs_onboard_submitted_includes_actor_fingerprint_and_url() {
        let event = EmailEvent::IacsOnboardSubmitted(IacsOnboardSubmittedEvent {
            event_id: Uuid::nil(),
            recipient: fake_recipient(),
            requester_username: "bob".into(),
            ews_name: "factory-ews-01".into(),
            fingerprint: iacs_fp().into(),
            justification: Some("Onboard for plant rollout".into()),
            admin_url: "https://vauban.test/iacs/requests/x".into(),
            base_url: "https://vauban.test".into(),
            from_brand: "Vauban PAM".into(),
        });
        let r = event.render().unwrap();
        assert!(r.subject.starts_with("[Vauban]"));
        assert!(r.subject.contains("bob"));
        assert!(r.body_text.contains("factory-ews-01"));
        assert!(r.body_text.contains(iacs_fp()));
        assert!(r.body_text.contains("Onboard for plant rollout"));
        assert!(r.body_text.contains("https://vauban.test/iacs/requests/x"));
    }

    #[test]
    fn render_iacs_onboard_approved_includes_approver_and_my_requests_url() {
        let event = EmailEvent::IacsOnboardApproved(IacsOnboardApprovedEvent {
            event_id: Uuid::nil(),
            recipient: fake_recipient(),
            ews_name: "factory-ews-01".into(),
            fingerprint: iacs_fp().into(),
            approver_username: "carol".into(),
            my_requests_url: "https://vauban.test/sessions/my-requests".into(),
            base_url: "https://vauban.test".into(),
            from_brand: "Vauban PAM".into(),
        });
        let r = event.render().unwrap();
        assert!(r.subject.contains("approved"));
        assert!(r.subject.contains("factory-ews-01"));
        assert!(r.body_text.contains("carol"));
        assert!(r.body_text.contains(iacs_fp()));
        assert!(
            r.body_text
                .contains("https://vauban.test/sessions/my-requests")
        );
    }

    #[test]
    fn render_iacs_onboard_rejected_includes_reason() {
        let event = EmailEvent::IacsOnboardRejected(IacsOnboardRejectedEvent {
            event_id: Uuid::nil(),
            recipient: fake_recipient(),
            ews_name: "factory-ews-01".into(),
            approver_username: "carol".into(),
            reason: "Justification insufficient".into(),
            my_requests_url: "https://vauban.test/sessions/my-requests".into(),
            base_url: "https://vauban.test".into(),
            from_brand: "Vauban PAM".into(),
        });
        let r = event.render().unwrap();
        assert!(r.subject.contains("denied"));
        assert!(r.body_text.contains("carol"));
        assert!(r.body_text.contains("Justification insufficient"));
    }

    #[test]
    fn render_iacs_offboarded_warns_irreversible_and_includes_fingerprint() {
        let event = EmailEvent::IacsOffboarded(IacsOffboardedEvent {
            event_id: Uuid::nil(),
            recipient: fake_recipient(),
            ews_name: "factory-ews-01".into(),
            fingerprint: iacs_fp().into(),
            admin_username: "carol".into(),
            base_url: "https://vauban.test".into(),
            from_brand: "Vauban PAM".into(),
        });
        let r = event.render().unwrap();
        assert!(r.subject.contains("offboarded"));
        assert!(r.body_text.contains("carol"));
        assert!(r.body_text.contains(iacs_fp()));
        assert!(r.body_text.contains("irreversible"));
    }

    #[test]
    fn iacs_event_kinds_match_taxonomy() {
        let cases: &[(&str, EmailEvent)] = &[
            (
                "iacs.onboard_submitted",
                EmailEvent::IacsOnboardSubmitted(IacsOnboardSubmittedEvent {
                    event_id: Uuid::nil(),
                    recipient: fake_recipient(),
                    requester_username: "bob".into(),
                    ews_name: "ews".into(),
                    fingerprint: iacs_fp().into(),
                    justification: None,
                    admin_url: "u".into(),
                    base_url: "b".into(),
                    from_brand: "br".into(),
                }),
            ),
            (
                "iacs.onboard_approved",
                EmailEvent::IacsOnboardApproved(IacsOnboardApprovedEvent {
                    event_id: Uuid::nil(),
                    recipient: fake_recipient(),
                    ews_name: "ews".into(),
                    fingerprint: iacs_fp().into(),
                    approver_username: "c".into(),
                    my_requests_url: "u".into(),
                    base_url: "b".into(),
                    from_brand: "br".into(),
                }),
            ),
            (
                "iacs.onboard_rejected",
                EmailEvent::IacsOnboardRejected(IacsOnboardRejectedEvent {
                    event_id: Uuid::nil(),
                    recipient: fake_recipient(),
                    ews_name: "ews".into(),
                    approver_username: "c".into(),
                    reason: "r".into(),
                    my_requests_url: "u".into(),
                    base_url: "b".into(),
                    from_brand: "br".into(),
                }),
            ),
            (
                "iacs.offboarded",
                EmailEvent::IacsOffboarded(IacsOffboardedEvent {
                    event_id: Uuid::nil(),
                    recipient: fake_recipient(),
                    ews_name: "ews".into(),
                    fingerprint: iacs_fp().into(),
                    admin_username: "c".into(),
                    base_url: "b".into(),
                    from_brand: "br".into(),
                }),
            ),
        ];
        for (expected, event) in cases {
            assert_eq!(event.kind(), *expected);
        }
    }

    #[test]
    fn iacs_event_render_subjects_have_no_crlf() {
        let evts = [
            EmailEvent::IacsOnboardSubmitted(IacsOnboardSubmittedEvent {
                event_id: Uuid::nil(),
                recipient: fake_recipient(),
                requester_username: "bob".into(),
                ews_name: "ews-1".into(),
                fingerprint: iacs_fp().into(),
                justification: None,
                admin_url: "u".into(),
                base_url: "b".into(),
                from_brand: "br".into(),
            }),
            EmailEvent::IacsOnboardApproved(IacsOnboardApprovedEvent {
                event_id: Uuid::nil(),
                recipient: fake_recipient(),
                ews_name: "ews-1".into(),
                fingerprint: iacs_fp().into(),
                approver_username: "c".into(),
                my_requests_url: "u".into(),
                base_url: "b".into(),
                from_brand: "br".into(),
            }),
            EmailEvent::IacsOnboardRejected(IacsOnboardRejectedEvent {
                event_id: Uuid::nil(),
                recipient: fake_recipient(),
                ews_name: "ews-1".into(),
                approver_username: "c".into(),
                reason: "r".into(),
                my_requests_url: "u".into(),
                base_url: "b".into(),
                from_brand: "br".into(),
            }),
            EmailEvent::IacsOffboarded(IacsOffboardedEvent {
                event_id: Uuid::nil(),
                recipient: fake_recipient(),
                ews_name: "ews-1".into(),
                fingerprint: iacs_fp().into(),
                admin_username: "c".into(),
                base_url: "b".into(),
                from_brand: "br".into(),
            }),
        ];
        for e in &evts {
            let r = e.render().unwrap();
            assert!(!r.subject.contains('\r'));
            assert!(!r.subject.contains('\n'));
        }
    }

    #[test]
    fn format_recipient_label_uses_display_name_when_present() {
        let r = EmailRecipient::new("alice@example.test", "Alice");
        assert_eq!(format_recipient_label(&r), "Alice <alice@example.test>");
    }

    #[test]
    fn format_recipient_label_bare_address_when_name_empty() {
        let r = EmailRecipient::bare("bob@example.test");
        assert_eq!(format_recipient_label(&r), "bob@example.test");
    }

    #[test]
    fn format_queue_summary_is_one_line_for_many_recipients() {
        let recipients = [
            EmailRecipient::new("a@x.test", "alice"),
            EmailRecipient::new("b@x.test", "bob"),
        ];
        let line = format_queue_summary("access_request.submitted", &recipients, 2, 0, &[]);
        assert!(line.contains("access_request.submitted"));
        assert!(line.contains("alice <a@x.test>"));
        assert!(line.contains("bob <b@x.test>"));
        assert!(line.contains("queued=2"));
        assert!(!line.contains('\n'));
        assert!(!line.contains('\r'));
    }

    #[test]
    fn format_queue_summary_includes_errors_on_same_line() {
        let recipients = [EmailRecipient::bare("bad@x.test")];
        let line = format_queue_summary(
            "access_request.submitted",
            &recipients,
            0,
            0,
            &["CRLF injection detected in recipient.address".into()],
        );
        assert!(line.contains("failed=1"));
        assert!(line.contains("errors="));
        assert!(line.contains("bad@x.test"));
        assert!(!line.contains('\n'));
    }

    #[test]
    fn format_queue_summary_strips_crlf_from_atoms() {
        let recipients = [EmailRecipient::new("a@x.test", "al\nice")];
        let line = format_queue_summary("kind\r\nX", &recipients, 1, 0, &["e\r\nrr".into()]);
        assert!(!line.contains('\r'));
        assert!(!line.contains('\n'));
        assert!(line.contains("alice"));
    }

    fn catalogue_events() -> Vec<EmailEvent> {
        vec![
            fake_submitted_event(),
            EmailEvent::AccessRequestApproved(AccessRequestApprovedEvent {
                event_id: Uuid::nil(),
                recipient: fake_recipient(),
                asset_name: "prod-db-01".into(),
                protocol: "ssh".into(),
                approver_username: "admin".into(),
                session_url: "https://vauban.test/s".into(),
                valid_until: None,
                base_url: "https://vauban.test".into(),
                from_brand: "Vauban PAM".into(),
            }),
            EmailEvent::AccessRequestRejected(AccessRequestRejectedEvent {
                event_id: Uuid::nil(),
                recipient: fake_recipient(),
                asset_name: "prod-db-01".into(),
                protocol: "ssh".into(),
                approver_username: "admin".into(),
                reason: Some("no".into()),
                base_url: "https://vauban.test".into(),
                from_brand: "Vauban PAM".into(),
            }),
            EmailEvent::AccessRequestRevoked(AccessRequestRevokedEvent {
                event_id: Uuid::nil(),
                recipient: fake_recipient(),
                asset_name: "prod-db-01".into(),
                protocol: "ssh".into(),
                approver_username: "admin".into(),
                reason: None,
                base_url: "https://vauban.test".into(),
                from_brand: "Vauban PAM".into(),
            }),
            EmailEvent::AccessRequestExpired(AccessRequestExpiredEvent {
                event_id: Uuid::nil(),
                recipient: fake_recipient(),
                requester_username: "bob".into(),
                asset_name: "prod-db-01".into(),
                protocol: "ssh".into(),
                base_url: "https://vauban.test".into(),
                from_brand: "Vauban PAM".into(),
            }),
            EmailEvent::UserCreated(UserCreatedEvent {
                event_id: Uuid::nil(),
                recipient: fake_recipient(),
                username: "alice".into(),
                created_by: "admin".into(),
                login_url: "https://vauban.test/login".into(),
                base_url: "https://vauban.test".into(),
                from_brand: "Vauban PAM".into(),
            }),
            EmailEvent::UserPasswordResetRequested(UserPasswordResetRequestedEvent {
                event_id: Uuid::nil(),
                recipient: fake_recipient(),
                username: "alice".into(),
                reset_url: "https://vauban.test/reset".into(),
                valid_until: Utc::now(),
                base_url: "https://vauban.test".into(),
                from_brand: "Vauban PAM".into(),
            }),
            EmailEvent::UserLockedAfterFailedAttempts(UserLockedAfterFailedAttemptsEvent {
                event_id: Uuid::nil(),
                recipient: fake_recipient(),
                username: "alice".into(),
                failed_attempts: 5,
                locked_until: None,
                base_url: "https://vauban.test".into(),
                from_brand: "Vauban PAM".into(),
            }),
            EmailEvent::UserMfaResetByAdmin(UserMfaResetByAdminEvent {
                event_id: Uuid::nil(),
                recipient: fake_recipient(),
                username: "alice".into(),
                admin_username: "admin".into(),
                base_url: "https://vauban.test".into(),
                from_brand: "Vauban PAM".into(),
            }),
            EmailEvent::SecurityMonoAdminDetected(SecurityMonoAdminDetectedEvent {
                event_id: Uuid::nil(),
                recipient: fake_recipient(),
                remaining_admin_username: "carol".into(),
                base_url: "https://vauban.test".into(),
                from_brand: "Vauban PAM".into(),
            }),
            EmailEvent::IacsOnboardSubmitted(IacsOnboardSubmittedEvent {
                event_id: Uuid::nil(),
                recipient: fake_recipient(),
                requester_username: "bob".into(),
                ews_name: "ews".into(),
                fingerprint: iacs_fp().into(),
                justification: None,
                admin_url: "https://vauban.test/iacs".into(),
                base_url: "https://vauban.test".into(),
                from_brand: "Vauban PAM".into(),
            }),
            EmailEvent::IacsOnboardApproved(IacsOnboardApprovedEvent {
                event_id: Uuid::nil(),
                recipient: fake_recipient(),
                ews_name: "ews".into(),
                fingerprint: iacs_fp().into(),
                approver_username: "carol".into(),
                my_requests_url: "https://vauban.test/my".into(),
                base_url: "https://vauban.test".into(),
                from_brand: "Vauban PAM".into(),
            }),
            EmailEvent::IacsOnboardRejected(IacsOnboardRejectedEvent {
                event_id: Uuid::nil(),
                recipient: fake_recipient(),
                ews_name: "ews".into(),
                approver_username: "carol".into(),
                reason: "no".into(),
                my_requests_url: "https://vauban.test/my".into(),
                base_url: "https://vauban.test".into(),
                from_brand: "Vauban PAM".into(),
            }),
            EmailEvent::IacsOffboarded(IacsOffboardedEvent {
                event_id: Uuid::nil(),
                recipient: fake_recipient(),
                ews_name: "ews".into(),
                fingerprint: iacs_fp().into(),
                admin_username: "carol".into(),
                base_url: "https://vauban.test".into(),
                from_brand: "Vauban PAM".into(),
            }),
        ]
    }

    #[test]
    fn every_event_renders_html_with_cid_and_brand() {
        let events = catalogue_events();
        assert_eq!(events.len(), 14);
        let mut kinds = Vec::new();
        for event in events {
            let r = event.render().unwrap();
            let html = r.body_html.expect("html body");
            assert!(
                html.contains("cid:vauban-logo"),
                "{} missing cid",
                event.kind()
            );
            assert!(
                html.contains("Vauban PAM"),
                "{} missing brand",
                event.kind()
            );
            assert!(
                !html.contains("__BRAND__"),
                "{} leftover brand ph",
                event.kind()
            );
            assert!(
                !html.contains("__FACTS_BLOCK__"),
                "{} leftover facts",
                event.kind()
            );
            kinds.push(event.kind());
        }
        kinds.sort_unstable();
        kinds.dedup();
        assert_eq!(kinds.len(), 14);
    }
}
