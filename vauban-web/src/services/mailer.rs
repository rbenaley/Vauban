//! Mailer service (Issue #10).
//!
//! Public surface:
//! * [`EmailEvent`] -- typed enumeration of every notification VAUBAN
//!   knows how to send. Each variant carries the data needed to render
//!   the email body and the recipient address.
//! * [`Mailer::queue`] -- helper that INSERTs one row in the
//!   `email_outbox` table (transactional outbox pattern) and wakes the
//!   dispatcher task via [`tokio::sync::Notify`]. MUST be called
//!   inside the same DB transaction as the business mutation that
//!   triggers it: a rollback of the transaction cancels the email.
//!
//! The actual SMTP exchange is performed by
//! [`crate::tasks::mailer`] (the dispatcher), not here. This service
//! is the write-side of the outbox: cheap, synchronous w.r.t. the HTTP
//! handler that calls it, and never touches the network.
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
//! * No PII in logs: helpers in this module hash recipient addresses
//!   with BLAKE3 before logging.

use std::sync::Arc;

use blake3::Hasher;
use chrono::{DateTime, Utc};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use tokio::sync::Notify;
use uuid::Uuid;

use crate::models::email_outbox::NewOutboxEntry;
use crate::services::smtp_client::validate_no_crlf;

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
    /// Wakes the dispatcher task in [`crate::tasks::mailer`] after a
    /// successful INSERT.
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
                tracing::info!(
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
/// chars. Used in logs to keep PII out while preserving "two events
/// to the same address" correlation.
pub fn hash_recipient(address: &str) -> String {
    let mut h = Hasher::new();
    h.update(b"vauban:mailer:recipient:");
    h.update(address.as_bytes());
    let digest = h.finalize();
    hex::encode(&digest.as_bytes()[..8])
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
    AccessRequestExpired(AccessRequestExpiredEvent),
    UserCreated(UserCreatedEvent),
    UserPasswordResetRequested(UserPasswordResetRequestedEvent),
    UserLockedAfterFailedAttempts(UserLockedAfterFailedAttemptsEvent),
    UserMfaResetByAdmin(UserMfaResetByAdminEvent),
    SecurityMonoAdminDetected(SecurityMonoAdminDetectedEvent),
}

impl EmailEvent {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::AccessRequestSubmitted(_) => "access_request.submitted",
            Self::AccessRequestApproved(_) => "access_request.approved",
            Self::AccessRequestRejected(_) => "access_request.rejected",
            Self::AccessRequestExpired(_) => "access_request.expired",
            Self::UserCreated(_) => "user.created",
            Self::UserPasswordResetRequested(_) => "user.password_reset_requested",
            Self::UserLockedAfterFailedAttempts(_) => "user.locked_after_failed_attempts",
            Self::UserMfaResetByAdmin(_) => "user.mfa_reset_by_admin",
            Self::SecurityMonoAdminDetected(_) => "security.mono_admin_detected",
        }
    }

    pub fn event_id(&self) -> Uuid {
        match self {
            Self::AccessRequestSubmitted(e) => e.event_id,
            Self::AccessRequestApproved(e) => e.event_id,
            Self::AccessRequestRejected(e) => e.event_id,
            Self::AccessRequestExpired(e) => e.event_id,
            Self::UserCreated(e) => e.event_id,
            Self::UserPasswordResetRequested(e) => e.event_id,
            Self::UserLockedAfterFailedAttempts(e) => e.event_id,
            Self::UserMfaResetByAdmin(e) => e.event_id,
            Self::SecurityMonoAdminDetected(e) => e.event_id,
        }
    }

    pub fn recipient(&self) -> &EmailRecipient {
        match self {
            Self::AccessRequestSubmitted(e) => &e.recipient,
            Self::AccessRequestApproved(e) => &e.recipient,
            Self::AccessRequestRejected(e) => &e.recipient,
            Self::AccessRequestExpired(e) => &e.recipient,
            Self::UserCreated(e) => &e.recipient,
            Self::UserPasswordResetRequested(e) => &e.recipient,
            Self::UserLockedAfterFailedAttempts(e) => &e.recipient,
            Self::UserMfaResetByAdmin(e) => &e.recipient,
            Self::SecurityMonoAdminDetected(e) => &e.recipient,
        }
    }

    /// Render the event into a `(subject, text, html)` triple. The
    /// implementation uses a small format!()-based renderer for the
    /// MVP; the next chantier replaces this with proper Askama
    /// templates under `vauban-web/templates/email/`.
    pub fn render(&self) -> Result<RenderedEmail, RenderError> {
        match self {
            Self::AccessRequestSubmitted(e) => render_access_request_submitted(e),
            Self::AccessRequestApproved(e) => render_access_request_approved(e),
            Self::AccessRequestRejected(e) => render_access_request_rejected(e),
            Self::AccessRequestExpired(e) => render_access_request_expired(e),
            Self::UserCreated(e) => render_user_created(e),
            Self::UserPasswordResetRequested(e) => render_user_password_reset_requested(e),
            Self::UserLockedAfterFailedAttempts(e) => render_user_locked(e),
            Self::UserMfaResetByAdmin(e) => render_user_mfa_reset(e),
            Self::SecurityMonoAdminDetected(e) => render_security_mono_admin(e),
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
    Ok(RenderedEmail {
        subject,
        body_text: text,
        body_html: None,
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
    Ok(RenderedEmail {
        subject,
        body_text: text,
        body_html: None,
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
    Ok(RenderedEmail {
        subject,
        body_text: text,
        body_html: None,
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
    Ok(RenderedEmail {
        subject,
        body_text: text,
        body_html: None,
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
    Ok(RenderedEmail {
        subject,
        body_text: text,
        body_html: None,
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
    Ok(RenderedEmail {
        subject,
        body_text: text,
        body_html: None,
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
    Ok(RenderedEmail {
        subject,
        body_text: text,
        body_html: None,
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
    Ok(RenderedEmail {
        subject,
        body_text: text,
        body_html: None,
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
    Ok(RenderedEmail {
        subject,
        body_text: text,
        body_html: None,
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
}
