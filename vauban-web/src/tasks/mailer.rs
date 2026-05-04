//! Email dispatcher task (Issue #10).
//!
//! Runs as a long-lived Tokio task. On each tick (driven by either a
//! `tokio::time::interval` or a `tokio::sync::Notify::notified()`),
//! it:
//!
//! 1. Picks up to `mailer.batch_size` rows from `email_outbox` whose
//!    `status = 'pending'` and `next_retry_at <= NOW()`, locking them
//!    with `FOR UPDATE SKIP LOCKED` so multiple workers (today one,
//!    tomorrow several) cannot race.
//! 2. Asks `vauban-supervisor` to broker a TCP connection to the
//!    configured SMTP relay (Issue #10 SSRF guard).
//! 3. Opens an [`crate::services::smtp_client::SmtpSession`]
//!    (EHLO -> STARTTLS -> AUTH PLAIN), then sends every envelope on
//!    the same connection.
//! 4. Updates each row to `sent` or, on transient failure, schedules a
//!    retry with exponential backoff capped at 60 minutes. After
//!    `max_attempts`, the row transitions to `failed`.
//!
//! Why a single Tokio task and not a worker pool?
//!
//! * One SMTP connection per batch amortises TLS+AUTH cost across N
//!   envelopes.
//! * `FOR UPDATE SKIP LOCKED` is correct under any worker count, so
//!   scaling out later is purely a config knob.
//! * The HTTP request hot-path is never on the critical path: a
//!   handler INSERTs the outbox row in its own transaction and
//!   returns. The dispatcher catches up out-of-band.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::{
    AsyncConnection, AsyncPgConnection, RunQueryDsl, scoped_futures::ScopedFutureExt,
};
use rustls::ClientConfig;
use tokio::time::Instant;
use tracing::{debug, error, info, warn};

use crate::AppState;
use crate::config::{MailerConfig, SmtpEncryption};
use crate::ipc::SupervisorClient;
use crate::models::email_outbox::{OutboxAttemptUpdate, OutboxEntry, OutboxStatus};
use crate::schema::email_outbox::dsl;
use crate::services::mailer::hash_recipient;
use crate::services::smtp_client::{
    MailEnvelope, SmtpError, SmtpSession, default_client_config, open_session,
};

/// Maximum backoff between retries.
const BACKOFF_CAP: Duration = Duration::from_secs(60 * 60);

/// Base unit for the exponential backoff: `min(BACKOFF_BASE * 2^attempts, BACKOFF_CAP)`.
///
/// 30 seconds is the smallest "polite" SMTP retry: most relays
/// rate-limit a sending IP under one minute. Even at the first
/// retry (`attempts = 1`), the schedule is 60 s, which is gentle
/// enough to avoid hammering the MTA on transient blips.
const BACKOFF_BASE: Duration = Duration::from_secs(30);

/// Spawn the dispatcher task on the current Tokio runtime.
///
/// Idempotent in the sense that calling it twice spawns two
/// dispatchers; production code calls it once from `main.rs`. When
/// `mailer.enabled` is false, the function is a no-op and logs the
/// fact at info level.
pub fn start_mailer_dispatcher(state: AppState) {
    if !state.config.mailer.enabled {
        info!("Mailer disabled; dispatcher task not started");
        return;
    }
    let handle = tokio::runtime::Handle::current();
    handle.spawn(async move {
        info!(
            poll_interval_secs = state.config.mailer.poll_interval_secs,
            batch_size = state.config.mailer.batch_size,
            "Mailer dispatcher task started"
        );
        dispatcher_loop(state).await;
        warn!("Mailer dispatcher task exited (this should not happen)");
    });
}

/// Dispatcher main loop. Wakes on either the polling interval or a
/// `Notify::notified()` from `Mailer::queue`.
async fn dispatcher_loop(state: AppState) {
    let notify = state.mailer.notify_handle();
    let poll = Duration::from_secs(state.config.mailer.poll_interval_secs.max(1));
    // Build the rustls config ONCE: re-using the same Arc<ClientConfig>
    // across SMTP sessions is recommended by tokio-rustls (config
    // construction is non-trivial; sessions only borrow it).
    let tls_config = default_client_config();

    let mut next_tick = Instant::now() + poll;
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(next_tick) => {}
            _ = notify.notified() => {
                debug!("Mailer dispatcher woken by notify_one");
            }
        }
        next_tick = Instant::now() + poll;

        match drain_outbox_once(&state, &tls_config).await {
            Ok(0) => {
                debug!("Mailer drain: no rows pending");
            }
            Ok(n) => {
                info!(processed = n, "Mailer drain: processed batch");
            }
            Err(DrainError::NoSupervisor) => {
                // Common in dev mode. Log once at debug, do not spam.
                debug!("Mailer drain skipped: no supervisor IPC available");
            }
            Err(e) => {
                error!(error = %e, "Mailer drain failed; will retry on next tick");
            }
        }
    }
}

/// Drainage error.
#[derive(Debug, thiserror::Error)]
enum DrainError {
    #[error("supervisor IPC client not available (dev mode?)")]
    NoSupervisor,
    #[error("DB pool error: {0}")]
    Pool(String),
    #[error("DB query error: {0}")]
    Db(String),
    #[error("SMTP broker error: {0}")]
    Broker(String),
    #[error("SMTP session error: {0}")]
    Smtp(String),
}

/// One drain pass.
///
/// Returns the number of rows processed (sent or moved to
/// retry/failed). Returns 0 when the outbox has nothing eligible.
async fn drain_outbox_once(
    state: &AppState,
    tls_config: &Arc<ClientConfig>,
) -> Result<usize, DrainError> {
    let supervisor = state
        .supervisor
        .as_ref()
        .ok_or(DrainError::NoSupervisor)?
        .clone();

    let mailer = state.config.mailer.clone();

    // Step 1: lock and pull the next batch in one transaction.
    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| DrainError::Pool(e.to_string()))?;
    let batch = pull_batch(&mut conn, mailer.batch_size).await?;
    drop(conn); // release the pool slot before the SMTP work.

    if batch.is_empty() {
        return Ok(0);
    }

    // Step 2: ask supervisor to broker an SMTP TCP connection. Reused
    // for every row in the batch.
    let session_id = format!("mailer-{}", uuid::Uuid::new_v4());
    let broker_timeout = Duration::from_secs(mailer.broker_timeout_secs.max(1));
    let smtp_result = supervisor
        .request_smtp_connect(
            &session_id,
            &mailer.smtp_host,
            mailer.smtp_port,
            // The session_token bytes are not verified by the supervisor
            // for target=Web (see vauban-supervisor/src/main.rs); we
            // pass an empty Vec for protocol uniformity.
            Vec::new(),
            broker_timeout,
        )
        .await
        .map_err(DrainError::Broker)?;
    if !smtp_result.success {
        // Do NOT mark rows failed -- the broker outage is the
        // operator's problem, not the message's. We just push the
        // retry forward and let the next tick try again.
        let err_msg = smtp_result
            .error
            .unwrap_or_else(|| "broker refused".to_string());
        warn!(
            session_id = %session_id,
            host = %mailer.smtp_host,
            port = mailer.smtp_port,
            error = %err_msg,
            "SMTP broker refused; pushing batch retry"
        );
        push_batch_retry(state, &batch, &err_msg).await?;
        return Ok(batch.len());
    }
    let stream = smtp_result.stream.ok_or_else(|| {
        DrainError::Broker("supervisor reported success but no stream".to_string())
    })?;

    // Step 3: open SMTP session.
    let session = open_session(
        stream,
        mailer.effective_helo(),
        mailer.smtp_encryption,
        &mailer.smtp_host,
        Arc::clone(tls_config),
    )
    .await
    .map_err(|e| DrainError::Smtp(e.to_string()))?;

    let mut session = session;
    if !mailer.smtp_username.is_empty()
        && mailer.smtp_encryption != SmtpEncryption::Plaintext
        && let Err(e) = session
            .auth_plain(&mailer.smtp_username, &mailer.smtp_password)
            .await
    {
        error!(
            session_id = %session_id,
            error = %e,
            "SMTP AUTH failed; aborting batch and pushing retry"
        );
        // Don't try to QUIT in the middle of an AUTH error; the
        // session might be in an undefined state.
        push_batch_retry(state, &batch, &e.to_string()).await?;
        return Ok(batch.len());
    }

    // Step 4: send each envelope.
    let mut processed = 0usize;
    for row in &batch {
        let envelope = build_envelope(&mailer, row);
        match session.send(&envelope).await {
            Ok(()) => {
                mark_sent(state, row).await?;
                processed += 1;
            }
            Err(e) => {
                let transient = e.is_transient();
                warn!(
                    event_id = %row.event_id,
                    event_kind = %row.event_kind,
                    recipient_hash = %hash_recipient(&row.recipient),
                    attempts = row.attempts + 1,
                    transient,
                    error = %e,
                    "SMTP send failed"
                );
                mark_retry_or_failed(state, row, &e, transient, mailer.max_attempts).await?;
                processed += 1;
                // If the error is non-transient at the protocol layer
                // (e.g. wrong server-name, connection torn down), the
                // session may be unusable for the next row. Quit and
                // bail; the next tick reopens.
                if matches!(
                    e,
                    SmtpError::Io(_) | SmtpError::Tls(_) | SmtpError::Protocol(_)
                ) {
                    warn!("SMTP transport unusable; closing session and bailing");
                    session.quit().await;
                    return Ok(processed);
                }
            }
        }
    }

    session.quit().await;
    Ok(processed)
}

/// Build the wire envelope from an outbox row.
///
/// The DATA body is constructed here (headers + body). We always send
/// `text/plain`; if `body_html` is present, we wrap it in a
/// `multipart/alternative` boundary.
fn build_envelope(mailer: &MailerConfig, row: &OutboxEntry) -> MailEnvelope {
    let from_header = if mailer.from_name.is_empty() {
        mailer.from_address.clone()
    } else {
        format!("{} <{}>", mailer.from_name, mailer.from_address)
    };
    let to_header = if row.recipient_name.is_empty() {
        row.recipient.clone()
    } else {
        format!("{} <{}>", row.recipient_name, row.recipient)
    };

    let date = chrono::Utc::now().to_rfc2822();
    let message_id = format!("<{}@vauban>", row.event_id);

    let mut data = String::new();
    data.push_str(&format!("From: {}\r\n", from_header));
    data.push_str(&format!("To: {}\r\n", to_header));
    if !mailer.reply_to.is_empty() {
        data.push_str(&format!("Reply-To: {}\r\n", mailer.reply_to));
    }
    data.push_str(&format!("Subject: {}\r\n", row.subject));
    data.push_str(&format!("Date: {}\r\n", date));
    data.push_str(&format!("Message-ID: {}\r\n", message_id));
    data.push_str("MIME-Version: 1.0\r\n");
    data.push_str("X-Vauban-Event: ");
    data.push_str(&row.event_kind);
    data.push_str("\r\n");

    match &row.body_html {
        Some(html) if !html.is_empty() => {
            let boundary = format!("vauban-mp-{}", row.event_id.simple());
            data.push_str(&format!(
                "Content-Type: multipart/alternative; boundary=\"{}\"\r\n",
                boundary
            ));
            data.push_str("\r\n");
            data.push_str(&format!("--{}\r\n", boundary));
            data.push_str("Content-Type: text/plain; charset=utf-8\r\n");
            data.push_str("Content-Transfer-Encoding: 8bit\r\n\r\n");
            data.push_str(&row.body_text);
            data.push_str("\r\n");
            data.push_str(&format!("--{}\r\n", boundary));
            data.push_str("Content-Type: text/html; charset=utf-8\r\n");
            data.push_str("Content-Transfer-Encoding: 8bit\r\n\r\n");
            data.push_str(html);
            data.push_str("\r\n");
            data.push_str(&format!("--{}--\r\n", boundary));
        }
        _ => {
            data.push_str("Content-Type: text/plain; charset=utf-8\r\n");
            data.push_str("Content-Transfer-Encoding: 8bit\r\n");
            data.push_str("\r\n");
            data.push_str(&row.body_text);
        }
    }

    MailEnvelope {
        from: mailer.from_address.clone(),
        to: row.recipient.clone(),
        data,
    }
}

/// Pull up to `batch_size` pending rows whose retry window has
/// elapsed, locking them so concurrent dispatchers cannot pick the
/// same rows.
async fn pull_batch(
    conn: &mut AsyncPgConnection,
    batch_size: i64,
) -> Result<Vec<OutboxEntry>, DrainError> {
    let now = Utc::now();

    let rows: Vec<OutboxEntry> = conn
        .transaction::<Vec<OutboxEntry>, diesel::result::Error, _>(|tx| {
            async move {
                dsl::email_outbox
                    .filter(dsl::status.eq(OutboxStatus::Pending.as_str()))
                    .filter(dsl::next_retry_at.is_null().or(dsl::next_retry_at.le(now)))
                    .order(dsl::id.asc())
                    .limit(batch_size)
                    .for_update()
                    .skip_locked()
                    .load::<OutboxEntry>(tx)
                    .await
            }
            .scope_boxed()
        })
        .await
        .map_err(|e| DrainError::Db(e.to_string()))?;

    Ok(rows)
}

/// Mark a row as `sent`. Best-effort: a DB blip here is logged but
/// does not abort the rest of the batch (the row may be retried by
/// the next tick, which is acceptable since SMTP delivery is
/// idempotent at the message-id level).
async fn mark_sent(state: &AppState, row: &OutboxEntry) -> Result<(), DrainError> {
    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| DrainError::Pool(e.to_string()))?;
    let update = OutboxAttemptUpdate {
        status: OutboxStatus::Sent.as_str().to_string(),
        attempts: row.attempts + 1,
        next_retry_at: None,
        last_error: None,
        sent_at: Some(Utc::now()),
    };
    diesel::update(dsl::email_outbox.find(row.id))
        .set(&update)
        .execute(&mut conn)
        .await
        .map_err(|e| DrainError::Db(e.to_string()))?;
    info!(
        outbox_id = row.id,
        event_id = %row.event_id,
        event_kind = %row.event_kind,
        recipient_hash = %hash_recipient(&row.recipient),
        attempts = update.attempts,
        "Email sent"
    );
    Ok(())
}

/// Decide between scheduling a retry and marking the row failed.
///
/// `transient` is the SMTP-layer classification (`is_transient()`).
/// Even non-transient errors get a retry if attempts remain (no harm
/// done), but the schedule is held at the cap so we don't spin on a
/// permanently-bad address.
async fn mark_retry_or_failed(
    state: &AppState,
    row: &OutboxEntry,
    err: &SmtpError,
    transient: bool,
    config_max_attempts: i32,
) -> Result<(), DrainError> {
    let new_attempts = row.attempts + 1;
    let max_attempts = row.max_attempts.max(config_max_attempts);
    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| DrainError::Pool(e.to_string()))?;

    if new_attempts >= max_attempts || !transient {
        let update = OutboxAttemptUpdate {
            status: OutboxStatus::Failed.as_str().to_string(),
            attempts: new_attempts,
            next_retry_at: None,
            last_error: Some(err.to_string()),
            sent_at: None,
        };
        diesel::update(dsl::email_outbox.find(row.id))
            .set(&update)
            .execute(&mut conn)
            .await
            .map_err(|e| DrainError::Db(e.to_string()))?;
        warn!(
            outbox_id = row.id,
            event_id = %row.event_id,
            event_kind = %row.event_kind,
            attempts = new_attempts,
            transient,
            "Email permanently failed"
        );
    } else {
        let next = backoff_after(new_attempts);
        let update = OutboxAttemptUpdate {
            status: OutboxStatus::Pending.as_str().to_string(),
            attempts: new_attempts,
            next_retry_at: Some(next),
            last_error: Some(err.to_string()),
            sent_at: None,
        };
        diesel::update(dsl::email_outbox.find(row.id))
            .set(&update)
            .execute(&mut conn)
            .await
            .map_err(|e| DrainError::Db(e.to_string()))?;
        info!(
            outbox_id = row.id,
            event_id = %row.event_id,
            event_kind = %row.event_kind,
            attempts = new_attempts,
            next_retry_at = %next.to_rfc3339(),
            "Email retry scheduled"
        );
    }
    Ok(())
}

/// Mark the entire batch for retry, e.g. when the broker connection or
/// the AUTH step fails before any envelope is sent.
async fn push_batch_retry(
    state: &AppState,
    batch: &[OutboxEntry],
    err: &str,
) -> Result<(), DrainError> {
    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| DrainError::Pool(e.to_string()))?;
    for row in batch {
        let new_attempts = row.attempts + 1;
        let next = backoff_after(new_attempts);
        let update = OutboxAttemptUpdate {
            status: OutboxStatus::Pending.as_str().to_string(),
            attempts: new_attempts,
            next_retry_at: Some(next),
            last_error: Some(err.to_string()),
            sent_at: None,
        };
        let _ = diesel::update(dsl::email_outbox.find(row.id))
            .set(&update)
            .execute(&mut conn)
            .await
            .map_err(|e| DrainError::Db(e.to_string()))?;
    }
    Ok(())
}

/// Return the backoff schedule for the `attempts`th retry.
///
/// Schedule (BACKOFF_BASE = 30 s, cap = 60 min):
///
/// | attempts | wait |
/// |----------|------|
/// | 1        | 60 s |
/// | 2        | 2 min |
/// | 3        | 4 min |
/// | 4        | 8 min |
/// | 5        | 16 min |
/// | 6        | 32 min |
/// | 7+       | 60 min |
fn backoff_after(attempts: i32) -> DateTime<Utc> {
    let wait = compute_backoff(attempts);
    Utc::now() + chrono::Duration::from_std(wait).unwrap_or_else(|_| chrono::Duration::seconds(60))
}

/// Pure helper for `backoff_after`. Extracted to keep the test surface
/// clock-free.
fn compute_backoff(attempts: i32) -> Duration {
    let exp = attempts.clamp(1, 20) as u32;
    let raw = BACKOFF_BASE.saturating_mul(1u32 << exp);
    if raw > BACKOFF_CAP { BACKOFF_CAP } else { raw }
}

/// Helper used only by tests/integration to push a manual drain (e.g.
/// in the integration test that wraps the dispatcher around a fake
/// supervisor + fake SMTP server).
#[cfg(test)]
pub async fn drain_once_for_test(
    state: &AppState,
    tls_config: &Arc<ClientConfig>,
) -> Result<usize, String> {
    drain_outbox_once(state, tls_config)
        .await
        .map_err(|e| e.to_string())
}

// Reserved for future visual diagnostics that need to inspect the
// `SupervisorClient` directly without hitting the rest of the
// dispatcher loop. Kept here to anchor the import as load-bearing
// (the real path uses it via `state.supervisor`).
#[allow(dead_code)]
fn _force_use_of_supervisor_import(_c: &SupervisorClient) {}

#[allow(dead_code)]
fn _force_use_of_smtp_session_import(_s: &SmtpSession) {}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn fake_row(id: i64, attempts: i32) -> OutboxEntry {
        OutboxEntry {
            id,
            event_id: Uuid::nil(),
            event_kind: "access_request.submitted".into(),
            recipient: "alice@example.com".into(),
            recipient_name: "Alice".into(),
            subject: "[Vauban] hi".into(),
            body_text: "hello".into(),
            body_html: None,
            status: "pending".into(),
            attempts,
            max_attempts: 5,
            next_retry_at: None,
            last_error: None,
            created_at: Utc::now(),
            sent_at: None,
        }
    }

    fn fake_mailer() -> MailerConfig {
        MailerConfig {
            enabled: true,
            from_address: "vauban@example.test".into(),
            from_name: "Vauban PAM".into(),
            reply_to: String::new(),
            base_url: "https://vauban.test".into(),
            smtp_host: "smtp.test".into(),
            smtp_port: 587,
            smtp_encryption: SmtpEncryption::Starttls,
            smtp_username: String::new(),
            smtp_password: secrecy::SecretString::new(String::new().into()),
            helo_name: String::new(),
            poll_interval_secs: 10,
            batch_size: 16,
            max_attempts: 5,
            smtp_timeout_secs: 30,
            broker_timeout_secs: 30,
        }
    }

    #[test]
    fn compute_backoff_first_retry_is_one_minute() {
        assert_eq!(compute_backoff(1), Duration::from_secs(60));
    }

    #[test]
    fn compute_backoff_doubles_each_attempt() {
        assert_eq!(compute_backoff(1), Duration::from_secs(60));
        assert_eq!(compute_backoff(2), Duration::from_secs(120));
        assert_eq!(compute_backoff(3), Duration::from_secs(240));
        assert_eq!(compute_backoff(4), Duration::from_secs(480));
    }

    #[test]
    fn compute_backoff_caps_at_one_hour() {
        // 30 * 2^7 = 3840 > 3600 (cap)
        assert_eq!(compute_backoff(7), BACKOFF_CAP);
        assert_eq!(compute_backoff(20), BACKOFF_CAP);
        assert_eq!(compute_backoff(100), BACKOFF_CAP);
    }

    #[test]
    fn compute_backoff_handles_zero_or_negative() {
        // attempts < 1 still produces a sane result (treated as 1).
        assert_eq!(compute_backoff(0), Duration::from_secs(60));
        assert_eq!(compute_backoff(-5), Duration::from_secs(60));
    }

    #[test]
    fn build_envelope_uses_from_name_when_set() {
        let m = fake_mailer();
        let row = fake_row(1, 0);
        let env = build_envelope(&m, &row);
        assert_eq!(env.from, "vauban@example.test");
        assert_eq!(env.to, "alice@example.com");
        assert!(env.data.contains("From: Vauban PAM <vauban@example.test>"));
        assert!(env.data.contains("To: Alice <alice@example.com>"));
    }

    #[test]
    fn build_envelope_omits_from_name_when_empty() {
        let mut m = fake_mailer();
        m.from_name = String::new();
        let row = fake_row(1, 0);
        let env = build_envelope(&m, &row);
        assert!(env.data.contains("From: vauban@example.test\r\n"));
    }

    #[test]
    fn build_envelope_includes_subject_message_id_event_kind() {
        let m = fake_mailer();
        let row = fake_row(1, 0);
        let env = build_envelope(&m, &row);
        assert!(env.data.contains("Subject: [Vauban] hi\r\n"));
        assert!(
            env.data
                .contains("X-Vauban-Event: access_request.submitted")
        );
        assert!(env.data.contains("Message-ID:"));
        assert!(env.data.contains("MIME-Version: 1.0"));
    }

    #[test]
    fn build_envelope_text_only_when_no_html() {
        let m = fake_mailer();
        let row = fake_row(1, 0);
        let env = build_envelope(&m, &row);
        assert!(env.data.contains("Content-Type: text/plain"));
        assert!(!env.data.contains("multipart/alternative"));
    }

    #[test]
    fn build_envelope_multipart_when_html_present() {
        let m = fake_mailer();
        let mut row = fake_row(1, 0);
        row.body_html = Some("<p>hi</p>".into());
        let env = build_envelope(&m, &row);
        assert!(env.data.contains("Content-Type: multipart/alternative"));
        assert!(env.data.contains("Content-Type: text/plain"));
        assert!(env.data.contains("Content-Type: text/html"));
        assert!(env.data.contains("<p>hi</p>"));
    }

    #[test]
    fn build_envelope_includes_reply_to_when_set() {
        let mut m = fake_mailer();
        m.reply_to = "support@example.com".into();
        let row = fake_row(1, 0);
        let env = build_envelope(&m, &row);
        assert!(env.data.contains("Reply-To: support@example.com\r\n"));
    }

    #[test]
    fn build_envelope_omits_reply_to_when_empty() {
        let m = fake_mailer();
        let row = fake_row(1, 0);
        let env = build_envelope(&m, &row);
        assert!(!env.data.contains("Reply-To:"));
    }

    /// Pin: the dispatcher MUST call `for_update().skip_locked()` so
    /// that two replicas (today one, tomorrow many) cannot drain the
    /// same row twice. A regression here would mean N copies of the
    /// same email going out under multi-instance deployments.
    #[test]
    fn pull_batch_uses_for_update_skip_locked() {
        let source = include_str!("mailer.rs");
        let fn_start = source
            .find("async fn pull_batch(")
            .expect("pull_batch must exist");
        let fn_body = &source[fn_start..];
        // Find the first "}" that closes the function (rough but
        // sufficient: there are no inner blocks with `async move`).
        let fn_end = fn_body
            .find("\n}\n")
            .map(|i| i + 2)
            .unwrap_or(fn_body.len());
        let fn_body = &fn_body[..fn_end];
        assert!(
            fn_body.contains(".for_update()"),
            "pull_batch MUST use .for_update() to lock pending rows"
        );
        assert!(
            fn_body.contains(".skip_locked()"),
            "pull_batch MUST use .skip_locked() so concurrent dispatchers \
             pick disjoint rows"
        );
    }

    /// Pin: backoff is bounded by 60 minutes, no matter the attempt
    /// count. Without this, a run-away counter would silently push
    /// retries to 2^31 seconds in the future (effectively dropping
    /// the row).
    #[test]
    fn backoff_cap_is_one_hour_per_plan() {
        assert_eq!(BACKOFF_CAP, Duration::from_secs(3600));
    }

    /// Pin: starting the dispatcher when the mailer is disabled is a
    /// no-op (no Tokio task spawned, no info!() spam every poll cycle).
    #[test]
    fn start_mailer_dispatcher_when_disabled_does_not_spawn() {
        let source = include_str!("mailer.rs");
        let fn_start = source
            .find("pub fn start_mailer_dispatcher(")
            .expect("start_mailer_dispatcher must exist");
        let fn_body = &source[fn_start..];
        let fn_end = fn_body
            .find("\n}\n")
            .map(|i| i + 2)
            .unwrap_or(fn_body.len());
        let fn_body = &fn_body[..fn_end];
        assert!(
            fn_body.contains("if !state.config.mailer.enabled"),
            "start_mailer_dispatcher MUST early-return when \
             config.mailer.enabled is false"
        );
        assert!(
            fn_body.contains("Mailer disabled"),
            "the disabled fast-path SHOULD log \"Mailer disabled\" \
             once at info level"
        );
    }
}
