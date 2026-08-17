//! Outbox drain loop (FOR UPDATE SKIP LOCKED + SMTP batch send).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::{
    AsyncConnection, AsyncPgConnection, RunQueryDsl, scoped_futures::ScopedFutureExt,
};
use rustls::ClientConfig;
use shared::messages::SmtpEncryption;
use shared::smtp::EMAIL_LOGO_CID;
use tokio::time::Instant;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Star-fort logo for `cid:vauban-logo` inline attachments.
pub const VAUBAN_LOGO_PNG: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/vauban-logo.png"
));

/// RFC 2045 / RFC 5321: fold base64 at 76 columns so DATA lines stay
/// under the 998-character hard limit (`Content-Transfer-Encoding: 8bit`
/// does not wrap for us).
const BASE64_FOLD: usize = 76;

use crate::broker::{answer_control, request_smtp_connect};
use crate::provision::MailerRuntime;
use crate::smtp_client::{MailEnvelope, SmtpError, client_config, open_session};
use shared::ipc::IpcChannel;
use shared::messages::{ControlMessage, Message};

const BACKOFF_CAP: Duration = Duration::from_hours(1);
const BACKOFF_BASE: Duration = Duration::from_secs(30);

diesel::table! {
    email_outbox (id) {
        id -> Int8,
        event_id -> Uuid,
        event_kind -> Varchar,
        recipient -> Varchar,
        recipient_name -> Varchar,
        subject -> Varchar,
        body_text -> Text,
        body_html -> Nullable<Text>,
        status -> Varchar,
        attempts -> Int4,
        max_attempts -> Int4,
        next_retry_at -> Nullable<Timestamptz>,
        last_error -> Nullable<Text>,
        created_at -> Timestamptz,
        sent_at -> Nullable<Timestamptz>,
    }
}

#[derive(Debug, Clone, Queryable, Selectable, Identifiable)]
#[diesel(table_name = email_outbox)]
pub struct OutboxEntry {
    pub id: i64,
    pub event_id: Uuid,
    pub event_kind: String,
    pub recipient: String,
    pub recipient_name: String,
    pub subject: String,
    pub body_text: String,
    pub body_html: Option<String>,
    pub status: String,
    pub attempts: i32,
    pub max_attempts: i32,
    pub next_retry_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub sent_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, AsChangeset)]
#[diesel(table_name = email_outbox)]
struct OutboxAttemptUpdate {
    status: String,
    attempts: i32,
    next_retry_at: Option<DateTime<Utc>>,
    last_error: Option<String>,
    sent_at: Option<DateTime<Utc>>,
}

pub struct DrainCtx {
    pub pool: diesel_async::pooled_connection::deadpool::Pool<AsyncPgConnection>,
    pub supervisor: IpcChannel,
    pub fd_passing_socket: i32,
    pub runtime: MailerRuntime,
    pub shutdown: Arc<AtomicBool>,
}

fn poll_supervisor_control(ctx: &DrainCtx) {
    while let Ok(ready) = shared::ipc::poll_readable(&[ctx.supervisor.read_fd()], 0) {
        if ready.is_empty() {
            break;
        }
        match ctx.supervisor.recv() {
            Ok(Message::Control(ControlMessage::Shutdown)) => {
                AtomicBool::store(&ctx.shutdown, true, Ordering::SeqCst);
                break;
            }
            Ok(Message::Control(ctrl)) => answer_control(&ctx.supervisor, ctrl),
            Ok(_) => break,
            Err(_) => break,
        }
    }
}

pub async fn dispatcher_loop(ctx: DrainCtx) {
    let tls_config = client_config(ctx.runtime.smtp_accept_invalid_certs);
    let poll = Duration::from_secs(ctx.runtime.poll_interval_secs.max(1));
    let mut next_tick = Instant::now() + poll;
    loop {
        if AtomicBool::load(&ctx.shutdown, Ordering::SeqCst) {
            info!("Mailer dispatcher shutting down");
            break;
        }
        poll_supervisor_control(&ctx);
        if AtomicBool::load(&ctx.shutdown, Ordering::SeqCst) {
            break;
        }

        tokio::time::sleep_until(next_tick).await;
        next_tick = Instant::now() + poll;

        poll_supervisor_control(&ctx);

        match drain_outbox_once(&ctx, &tls_config).await {
            Ok(0) => debug!("Mailer drain: no rows pending"),
            Ok(_) => {}
            Err(e) => error!(error = %e, "Mailer drain failed; will retry on next tick"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum DrainError {
    #[error("DB pool error: {0}")]
    Pool(String),
    #[error("DB query error: {0}")]
    Db(String),
    #[error("SMTP broker error: {0}")]
    Broker(String),
    #[error("SMTP session error: {0}")]
    Smtp(String),
}

async fn drain_outbox_once(
    ctx: &DrainCtx,
    tls_config: &Arc<ClientConfig>,
) -> Result<usize, DrainError> {
    let mut conn = ctx
        .pool
        .get()
        .await
        .map_err(|e| DrainError::Pool(e.to_string()))?;
    let batch = pull_batch(&mut conn, ctx.runtime.batch_size).await?;
    drop(conn);

    if batch.is_empty() {
        return Ok(0);
    }

    let host = ctx.runtime.smtp_host.clone();
    let port = ctx.runtime.smtp_port;
    let stream = request_smtp_connect(
        &ctx.supervisor,
        ctx.fd_passing_socket,
        &host,
        port,
        ctx.runtime.broker_timeout_secs,
    )
    .await
    .map_err(DrainError::Broker)?;

    let session = open_session(
        stream,
        ctx.runtime.effective_helo(),
        ctx.runtime.smtp_encryption,
        &host,
        Arc::clone(tls_config),
    )
    .await
    .map_err(|e| DrainError::Smtp(e.to_string()))?;

    let mut session = session;
    if !ctx.runtime.smtp_username.is_empty()
        && ctx.runtime.smtp_encryption != SmtpEncryption::Plaintext
        && let Err(e) = session
            .auth_plain(&ctx.runtime.smtp_username, &ctx.runtime.smtp_password)
            .await
    {
        let recipients = batch
            .iter()
            .map(mailbox_label)
            .collect::<Vec<_>>()
            .join(", ");
        error!(
            error = %e,
            batch = batch.len(),
            recipients = %recipients,
            "SMTP AUTH failed; batch will retry"
        );
        push_batch_retry(&ctx.pool, &batch, &e.to_string()).await?;
        return Ok(batch.len());
    }

    let mut processed = 0usize;
    let mut sent_to: Vec<String> = Vec::new();
    let mut failed_to: Vec<String> = Vec::new();
    let mut retrying_to: Vec<String> = Vec::new();
    for row in &batch {
        let envelope = build_envelope(&ctx.runtime, row);
        match session.send(&envelope).await {
            Ok(()) => {
                mark_sent(&ctx.pool, row).await?;
                processed += 1;
                sent_to.push(format!("{} -> {}", row.event_kind, mailbox_label(row)));
            }
            Err(e) => {
                let transient = e.is_transient();
                let disposition =
                    mark_retry_or_failed(&ctx.pool, row, &e, transient, ctx.runtime.max_attempts)
                        .await?;
                processed += 1;
                let entry = format!("{} -> {} ({})", row.event_kind, mailbox_label(row), e);
                match disposition {
                    DeliveryDisposition::Failed => failed_to.push(entry),
                    DeliveryDisposition::Retrying => retrying_to.push(entry),
                }
                if matches!(
                    e,
                    SmtpError::Io(_) | SmtpError::Tls(_) | SmtpError::Protocol(_)
                ) {
                    emit_drain_log(&sent_to, &failed_to, &retrying_to);
                    session.quit().await;
                    return Ok(processed);
                }
                if let Err(rset_err) = session.rset().await {
                    error!(
                        error = %rset_err,
                        "SMTP RSET failed after delivery error; closing session"
                    );
                    emit_drain_log(&sent_to, &failed_to, &retrying_to);
                    session.quit().await;
                    return Ok(processed);
                }
            }
        }
    }

    emit_drain_log(&sent_to, &failed_to, &retrying_to);
    session.quit().await;
    Ok(processed)
}

fn mailbox_label(row: &OutboxEntry) -> String {
    let address = row.recipient.replace(['\r', '\n'], "");
    if row.recipient_name.is_empty() {
        address
    } else {
        format!(
            "{} <{}>",
            row.recipient_name.replace(['\r', '\n'], ""),
            address
        )
    }
}

fn format_drain_detail(sent_to: &[String], failed_to: &[String], retrying_to: &[String]) -> String {
    let mut parts = Vec::new();
    if !sent_to.is_empty() {
        parts.push(format!("sent [{}]", sent_to.join("; ")));
    }
    if !failed_to.is_empty() {
        parts.push(format!("failed [{}]", failed_to.join("; ")));
    }
    if !retrying_to.is_empty() {
        parts.push(format!("retrying [{}]", retrying_to.join("; ")));
    }
    parts.join(" | ")
}

fn emit_drain_log(sent_to: &[String], failed_to: &[String], retrying_to: &[String]) {
    let sent = sent_to.len();
    let failed = failed_to.len();
    let retrying = retrying_to.len();
    let detail = format_drain_detail(sent_to, failed_to, retrying_to);
    if failed > 0 {
        error!(
            sent,
            failed,
            retrying,
            detail = %detail,
            "Mailer drain: delivery failed"
        );
    } else if retrying > 0 {
        warn!(
            sent,
            retrying,
            detail = %detail,
            "Mailer drain: retrying"
        );
    } else {
        info!(
            sent,
            detail = %detail,
            "Mailer drain: processed batch"
        );
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeliveryDisposition {
    Failed,
    Retrying,
}

pub fn build_envelope(runtime: &MailerRuntime, row: &OutboxEntry) -> MailEnvelope {
    let from_header = if runtime.from_name.is_empty() {
        runtime.from_address.clone()
    } else {
        format!("{} <{}>", runtime.from_name, runtime.from_address)
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
    if !runtime.reply_to.is_empty() {
        data.push_str(&format!("Reply-To: {}\r\n", runtime.reply_to));
    }
    data.push_str(&format!("Subject: {}\r\n", row.subject));
    data.push_str(&format!("Date: {}\r\n", date));
    data.push_str(&format!("Message-ID: {}\r\n", message_id));
    data.push_str("MIME-Version: 1.0\r\n");
    data.push_str("X-Vauban-Event: ");
    data.push_str(&row.event_kind);
    data.push_str("\r\n");

    match &row.body_html {
        Some(html) if !html.is_empty() && html_references_logo_cid(html) => {
            append_related_with_logo(&mut data, row, html);
        }
        Some(html) if !html.is_empty() => {
            append_alternative(&mut data, &row.body_text, html, &alt_boundary(row.event_id));
        }
        _ => {
            data.push_str("Content-Type: text/plain; charset=utf-8\r\n");
            data.push_str("Content-Transfer-Encoding: 8bit\r\n");
            data.push_str("\r\n");
            data.push_str(&row.body_text);
        }
    }

    MailEnvelope {
        from: runtime.from_address.clone(),
        to: row.recipient.clone(),
        data,
    }
}

fn html_references_logo_cid(html: &str) -> bool {
    let needle = format!("cid:{EMAIL_LOGO_CID}");
    html.contains(&needle)
}

fn alt_boundary(event_id: Uuid) -> String {
    format!("vauban-alt-{}", event_id.simple())
}

fn rel_boundary(event_id: Uuid) -> String {
    format!("vauban-rel-{}", event_id.simple())
}

fn append_alternative(data: &mut String, body_text: &str, html: &str, boundary: &str) {
    data.push_str("Content-Type: multipart/alternative; boundary=\"");
    data.push_str(boundary);
    data.push_str("\"\r\n\r\n");
    data.push_str("--");
    data.push_str(boundary);
    data.push_str("\r\nContent-Type: text/plain; charset=utf-8\r\n");
    data.push_str("Content-Transfer-Encoding: 8bit\r\n\r\n");
    data.push_str(body_text);
    data.push_str("\r\n--");
    data.push_str(boundary);
    data.push_str("\r\nContent-Type: text/html; charset=utf-8\r\n");
    data.push_str("Content-Transfer-Encoding: 8bit\r\n\r\n");
    data.push_str(html);
    data.push_str("\r\n--");
    data.push_str(boundary);
    data.push_str("--\r\n");
}

fn append_related_with_logo(data: &mut String, row: &OutboxEntry, html: &str) {
    let rel = rel_boundary(row.event_id);
    let alt = alt_boundary(row.event_id);
    data.push_str("Content-Type: multipart/related; type=\"multipart/alternative\"; boundary=\"");
    data.push_str(&rel);
    data.push_str("\"\r\n\r\n--");
    data.push_str(&rel);
    data.push_str("\r\n");
    append_alternative(data, &row.body_text, html, &alt);
    data.push_str("--");
    data.push_str(&rel);
    data.push_str("\r\nContent-Type: image/png\r\n");
    data.push_str("Content-Transfer-Encoding: base64\r\n");
    data.push_str("Content-ID: <");
    data.push_str(EMAIL_LOGO_CID);
    data.push_str(">\r\n");
    data.push_str("Content-Disposition: inline; filename=\"vauban-logo.png\"\r\n\r\n");
    data.push_str(&encode_base64_folded(VAUBAN_LOGO_PNG));
    data.push_str("\r\n--");
    data.push_str(&rel);
    data.push_str("--\r\n");
}

/// Encode `bytes` as RFC 2045 base64 with 76-column folding.
pub fn encode_base64_folded(bytes: &[u8]) -> String {
    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
    if encoded.is_empty() {
        return String::new();
    }
    let extra = encoded.len() / BASE64_FOLD;
    let mut out = String::with_capacity(encoded.len() + extra * 2);
    for (i, chunk) in encoded.as_bytes().chunks(BASE64_FOLD).enumerate() {
        if i > 0 {
            out.push_str("\r\n");
        }
        // STANDARD alphabet is ASCII; empty fallback keeps this unwrap-free.
        out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
    }
    out
}

async fn pull_batch(
    conn: &mut AsyncPgConnection,
    batch_size: i64,
) -> Result<Vec<OutboxEntry>, DrainError> {
    let now = Utc::now();
    conn.transaction::<Vec<OutboxEntry>, diesel::result::Error, _>(|tx| {
        async move {
            email_outbox::table
                .filter(email_outbox::status.eq("pending"))
                .filter(
                    email_outbox::next_retry_at
                        .is_null()
                        .or(email_outbox::next_retry_at.le(now)),
                )
                .order(email_outbox::id.asc())
                .limit(batch_size)
                .for_update()
                .skip_locked()
                .load::<OutboxEntry>(tx)
                .await
        }
        .scope_boxed()
    })
    .await
    .map_err(|e| DrainError::Db(e.to_string()))
}

async fn mark_sent(
    pool: &diesel_async::pooled_connection::deadpool::Pool<AsyncPgConnection>,
    row: &OutboxEntry,
) -> Result<(), DrainError> {
    let mut conn = pool
        .get()
        .await
        .map_err(|e| DrainError::Pool(e.to_string()))?;
    let update = OutboxAttemptUpdate {
        status: "sent".to_string(),
        attempts: row.attempts + 1,
        next_retry_at: None,
        last_error: None,
        sent_at: Some(Utc::now()),
    };
    diesel::update(email_outbox::table.find(row.id))
        .set(&update)
        .execute(&mut conn)
        .await
        .map_err(|e| DrainError::Db(e.to_string()))?;
    debug!(
        outbox_id = row.id,
        event_id = %row.event_id,
        event_kind = %row.event_kind,
        recipient = %row.recipient,
        "Email sent"
    );
    Ok(())
}

async fn mark_retry_or_failed(
    pool: &diesel_async::pooled_connection::deadpool::Pool<AsyncPgConnection>,
    row: &OutboxEntry,
    err: &SmtpError,
    transient: bool,
    config_max_attempts: i32,
) -> Result<DeliveryDisposition, DrainError> {
    let new_attempts = row.attempts + 1;
    let max_attempts = row.max_attempts.max(config_max_attempts);
    let disposition = delivery_disposition(new_attempts, max_attempts, transient);
    let mut conn = pool
        .get()
        .await
        .map_err(|e| DrainError::Pool(e.to_string()))?;

    if disposition == DeliveryDisposition::Failed {
        let update = OutboxAttemptUpdate {
            status: "failed".to_string(),
            attempts: new_attempts,
            next_retry_at: None,
            last_error: Some(err.to_string()),
            sent_at: None,
        };
        diesel::update(email_outbox::table.find(row.id))
            .set(&update)
            .execute(&mut conn)
            .await
            .map_err(|e| DrainError::Db(e.to_string()))?;
        Ok(disposition)
    } else {
        let next = backoff_after(new_attempts);
        let update = OutboxAttemptUpdate {
            status: "pending".to_string(),
            attempts: new_attempts,
            next_retry_at: Some(next),
            last_error: Some(err.to_string()),
            sent_at: None,
        };
        diesel::update(email_outbox::table.find(row.id))
            .set(&update)
            .execute(&mut conn)
            .await
            .map_err(|e| DrainError::Db(e.to_string()))?;
        Ok(disposition)
    }
}

fn delivery_disposition(
    new_attempts: i32,
    max_attempts: i32,
    transient: bool,
) -> DeliveryDisposition {
    if new_attempts >= max_attempts || !transient {
        DeliveryDisposition::Failed
    } else {
        DeliveryDisposition::Retrying
    }
}

async fn push_batch_retry(
    pool: &diesel_async::pooled_connection::deadpool::Pool<AsyncPgConnection>,
    batch: &[OutboxEntry],
    err: &str,
) -> Result<(), DrainError> {
    let mut conn = pool
        .get()
        .await
        .map_err(|e| DrainError::Pool(e.to_string()))?;
    for row in batch {
        let new_attempts = row.attempts + 1;
        let next = backoff_after(new_attempts);
        let update = OutboxAttemptUpdate {
            status: "pending".to_string(),
            attempts: new_attempts,
            next_retry_at: Some(next),
            last_error: Some(err.to_string()),
            sent_at: None,
        };
        diesel::update(email_outbox::table.find(row.id))
            .set(&update)
            .execute(&mut conn)
            .await
            .map_err(|e| DrainError::Db(e.to_string()))?;
    }
    Ok(())
}

fn backoff_after(attempts: i32) -> DateTime<Utc> {
    let wait = compute_backoff(attempts);
    Utc::now() + chrono::Duration::from_std(wait).unwrap_or_else(|_| chrono::Duration::seconds(60))
}

fn compute_backoff(attempts: i32) -> Duration {
    let exp = attempts.clamp(1, 20) as u32;
    let raw = BACKOFF_BASE.saturating_mul(1u32 << exp);
    if raw > BACKOFF_CAP { BACKOFF_CAP } else { raw }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn pull_batch_uses_for_update_skip_locked() {
        let source = include_str!("outbox.rs");
        assert!(source.contains(".for_update()"));
        assert!(source.contains(".skip_locked()"));
    }

    #[test]
    fn compute_backoff_caps_at_one_hour() {
        assert_eq!(compute_backoff(7), BACKOFF_CAP);
    }

    #[test]
    fn backoff_cap_is_one_hour() {
        assert_eq!(BACKOFF_CAP, Duration::from_hours(1));
        assert_eq!(Duration::from_hours(1), Duration::from_secs(3600));
    }

    #[test]
    fn delivery_disposition_550_is_failed_on_first_attempt() {
        assert_eq!(
            delivery_disposition(1, 5, false),
            DeliveryDisposition::Failed
        );
    }

    #[test]
    fn delivery_disposition_4xx_retries_until_budget() {
        assert_eq!(
            delivery_disposition(1, 5, true),
            DeliveryDisposition::Retrying
        );
        assert_eq!(
            delivery_disposition(5, 5, true),
            DeliveryDisposition::Failed
        );
    }

    #[test]
    fn format_drain_detail_is_one_line_with_who_and_error() {
        let sent = ["access_request.submitted -> alice <a@x.test>".to_string()];
        let failed = ["access_request.submitted -> bad <bad@x.test> (server returned non-success code 550: user unknown)".to_string()];
        let line = format_drain_detail(&sent, &failed, &[]);
        assert!(line.contains("alice <a@x.test>"));
        assert!(line.contains("bad <bad@x.test>"));
        assert!(line.contains("550"));
        assert!(!line.contains('\n'));
    }

    #[test]
    fn format_drain_detail_empty_when_nothing_processed() {
        assert_eq!(format_drain_detail(&[], &[], &[]), "");
    }

    #[test]
    fn drain_logs_delivery_failed_literal() {
        let source = include_str!("outbox.rs");
        assert!(source.contains("\"Mailer drain: delivery failed\""));
        assert!(source.contains("session.rset()"));
        assert!(
            source.contains("\"Email sent\""),
            "per-row send breadcrumb must remain (debug)"
        );
        let sent_idx = source.find("\"Email sent\"").expect("Email sent");
        let window = &source[sent_idx.saturating_sub(160)..sent_idx];
        assert!(
            window.contains("debug!"),
            "per-row Email sent must be debug!, not info!"
        );
    }

    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(32))]

        #[test]
        fn format_drain_detail_never_splits_lines(
            sent_n in 0usize..8,
            fail_n in 0usize..4,
        ) {
            let sent: Vec<String> = (0..sent_n)
                .map(|i| format!("kind -> user{i} <u{i}@x.test>"))
                .collect();
            let failed: Vec<String> = (0..fail_n)
                .map(|i| format!("kind -> bad{i} <b{i}@x.test> (550 user unknown)"))
                .collect();
            let line = format_drain_detail(&sent, &failed, &[]);
            proptest::prop_assert!(!line.contains('\r'));
            proptest::prop_assert!(!line.contains('\n'));
            for item in sent.iter().chain(failed.iter()) {
                if !line.is_empty() {
                    proptest::prop_assert!(line.contains(item));
                }
            }
        }
    }

    #[test]
    fn battle_format_drain_detail_under_contention() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let barrier = Arc::new(Barrier::new(8));
        let mut handles = Vec::new();
        for t in 0..8 {
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                for i in 0..64 {
                    let sent = [format!("k -> u{t}-{i} <a@x>")];
                    let failed = [format!("k -> b{t}-{i} <b@x> (550)")];
                    let line = format_drain_detail(&sent, &failed, &[]);
                    assert!(line.contains(&format!("u{t}-{i}")));
                    assert!(line.contains("550"));
                    assert!(!line.contains('\n'));
                }
            }));
        }
        for h in handles {
            h.join().expect("battle thread");
        }
    }

    fn test_runtime() -> MailerRuntime {
        use secrecy::SecretString;
        MailerRuntime {
            smtp_host: "smtp.test".into(),
            smtp_port: 25,
            smtp_encryption: SmtpEncryption::Plaintext,
            smtp_username: String::new(),
            smtp_password: SecretString::from(String::new()),
            helo_name: "vauban-test".into(),
            from_address: "vauban@example.test".into(),
            from_name: "Vauban PAM".into(),
            reply_to: String::new(),
            poll_interval_secs: 5,
            batch_size: 10,
            max_attempts: 5,
            smtp_timeout_secs: 10,
            broker_timeout_secs: 5,
            smtp_accept_invalid_certs: false,
        }
    }

    fn test_row(event_id: Uuid, body_text: &str, body_html: Option<String>) -> OutboxEntry {
        OutboxEntry {
            id: 1,
            event_id,
            event_kind: "access_request.rejected".into(),
            recipient: "alice@example.test".into(),
            recipient_name: "Alice".into(),
            subject: "Access denied".into(),
            body_text: body_text.to_string(),
            body_html,
            status: "pending".into(),
            attempts: 0,
            max_attempts: 5,
            next_retry_at: None,
            last_error: None,
            created_at: Utc::now(),
            sent_at: None,
        }
    }

    fn max_data_line_len(data: &str) -> usize {
        data.split('\n')
            .map(|line| line.strip_suffix('\r').unwrap_or(line).len())
            .max()
            .unwrap_or(0)
    }

    #[test]
    fn build_envelope_plain_text_when_html_absent() {
        let env = build_envelope(&test_runtime(), &test_row(Uuid::nil(), "plain body", None));
        assert!(env.data.contains("Content-Type: text/plain; charset=utf-8"));
        assert!(!env.data.contains("multipart/"));
        assert!(env.data.contains("plain body"));
    }

    #[test]
    fn build_envelope_plain_text_when_html_empty() {
        let env = build_envelope(
            &test_runtime(),
            &test_row(Uuid::nil(), "plain body", Some(String::new())),
        );
        assert!(!env.data.contains("multipart/"));
        assert!(env.data.contains("plain body"));
    }

    #[test]
    fn build_envelope_alternative_when_html_has_no_cid() {
        let html = "<p>hello</p>";
        let env = build_envelope(
            &test_runtime(),
            &test_row(Uuid::nil(), "plain", Some(html.into())),
        );
        assert!(env.data.contains("multipart/alternative"));
        assert!(!env.data.contains("multipart/related"));
        assert!(!env.data.contains("Content-ID:"));
        let plain_at = env.data.find("text/plain").expect("plain part");
        let html_at = env.data.find("text/html").expect("html part");
        assert!(plain_at < html_at, "text must precede html");
        assert!(env.data.contains("<p>hello</p>"));
    }

    #[test]
    fn build_envelope_related_when_html_references_cid() {
        let html = format!(r#"<img src="cid:{EMAIL_LOGO_CID}" alt="Vauban">"#);
        let event_id = Uuid::new_v4();
        let env = build_envelope(&test_runtime(), &test_row(event_id, "plain", Some(html)));
        assert!(env.data.contains("multipart/related"));
        assert!(env.data.contains("type=\"multipart/alternative\""));
        assert!(env.data.contains("Content-Disposition: inline"));
        assert!(
            env.data
                .contains(&format!("Content-ID: <{EMAIL_LOGO_CID}>")),
            "Content-ID must wrap the token in angle brackets"
        );
        assert!(
            !env.data
                .contains(&format!("Content-ID: {EMAIL_LOGO_CID}\r\n")),
            "Content-ID must not omit the brackets"
        );
        let rel = rel_boundary(event_id);
        let alt = alt_boundary(event_id);
        assert_ne!(rel, alt);
        assert!(!rel.starts_with(&alt));
        assert!(!alt.starts_with(&rel));
        assert!(env.data.contains(&format!("--{rel}--")));
        assert!(env.data.contains(&format!("--{alt}--")));
        let plain_at = env.data.find("text/plain").expect("plain");
        let html_at = env.data.find("text/html").expect("html");
        let image_at = env.data.find("Content-Type: image/png").expect("image");
        assert!(plain_at < html_at);
        assert!(html_at < image_at);
    }

    #[test]
    fn encode_base64_folded_wraps_at_76_and_round_trips() {
        use base64::Engine as _;
        let folded = encode_base64_folded(VAUBAN_LOGO_PNG);
        assert!(!folded.is_empty());
        for line in folded.split("\r\n") {
            assert!(
                line.len() <= BASE64_FOLD,
                "base64 line {} exceeds fold",
                line.len()
            );
        }
        let compact: String = folded.split("\r\n").collect();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(compact.as_bytes())
            .expect("decode");
        assert_eq!(decoded, VAUBAN_LOGO_PNG);
    }

    #[test]
    fn logo_png_is_a_real_png() {
        assert!(!VAUBAN_LOGO_PNG.is_empty());
        assert_eq!(&VAUBAN_LOGO_PNG[..8], b"\x89PNG\r\n\x1a\n");
    }

    #[test]
    fn email_logo_cid_comes_from_shared() {
        assert_eq!(EMAIL_LOGO_CID, shared::smtp::EMAIL_LOGO_CID);
        let source = include_str!("outbox.rs");
        assert!(
            source.contains("use shared::smtp::EMAIL_LOGO_CID"),
            "outbox must import EMAIL_LOGO_CID from shared"
        );
        let banned = ["const ", "EMAIL_LOGO_CID", ":"].concat();
        assert!(
            !source.contains(&banned),
            "outbox must not re-declare the CID constant"
        );
    }

    #[test]
    fn related_envelope_lines_stay_under_998() {
        let html = format!(r#"<img src="cid:{EMAIL_LOGO_CID}">"#);
        let env = build_envelope(
            &test_runtime(),
            &test_row(Uuid::new_v4(), "plain", Some(html)),
        );
        assert!(
            max_data_line_len(&env.data) <= 998,
            "longest DATA line is {}",
            max_data_line_len(&env.data)
        );
    }

    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(32))]

        #[test]
        fn build_envelope_boundaries_are_unique_and_closed(
            text in "[^\r\n]{0,400}",
            html_core in "[^\r\n]{0,400}",
            with_cid in proptest::bool::ANY,
        ) {
            let event_id = Uuid::new_v4();
            let html = if with_cid {
                format!("{html_core}<img src=\"cid:{EMAIL_LOGO_CID}\">")
            } else {
                html_core
            };
            let env = build_envelope(
                &test_runtime(),
                &test_row(event_id, &text, Some(html.clone())),
            );
            proptest::prop_assert!(max_data_line_len(&env.data) <= 998);
            if html.is_empty() {
                proptest::prop_assert!(!env.data.contains("multipart/"));
                return Ok(());
            }
            if with_cid {
                let rel = rel_boundary(event_id);
                let alt = alt_boundary(event_id);
                proptest::prop_assert_ne!(&rel, &alt);
                proptest::prop_assert!(!rel.starts_with(&alt));
                proptest::prop_assert!(!alt.starts_with(&rel));
                let rel_close = format!("--{rel}--");
                let alt_close = format!("--{alt}--");
                proptest::prop_assert!(env.data.contains(&rel_close));
                proptest::prop_assert!(env.data.contains(&alt_close));
                let rel_count = env.data.matches(&rel).count();
                let alt_count = env.data.matches(&alt).count();
                proptest::prop_assert!(rel_count >= 3);
                proptest::prop_assert!(alt_count >= 3);
            } else {
                proptest::prop_assert!(env.data.contains("multipart/alternative"));
                proptest::prop_assert!(!env.data.contains("multipart/related"));
            }
        }
    }

    #[test]
    fn battle_build_envelope_under_contention() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let barrier = Arc::new(Barrier::new(8));
        let mut handles = Vec::new();
        for t in 0..8 {
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                let runtime = test_runtime();
                for i in 0..32 {
                    let event_id = Uuid::new_v4();
                    let html = format!("<p>t{t}-i{i}</p><img src=\"cid:{EMAIL_LOGO_CID}\">");
                    let env = build_envelope(&runtime, &test_row(event_id, "plain", Some(html)));
                    let rel = rel_boundary(event_id);
                    let alt = alt_boundary(event_id);
                    assert!(env.data.contains(&rel));
                    assert!(env.data.contains(&alt));
                    assert!(env.data.contains(&format!("t{t}-i{i}")));
                    assert!(max_data_line_len(&env.data) <= 998);
                }
            }));
        }
        for h in handles {
            h.join().expect("battle thread");
        }
    }

    #[tokio::test]
    async fn e2e_related_envelope_survives_smtp_data_and_parses() {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
        use tokio::net::{TcpListener, TcpStream};

        use crate::smtp_client::SmtpSession;

        let html = format!(r#"<img src="cid:{EMAIL_LOGO_CID}" alt="x">"#);
        let event_id = Uuid::new_v4();
        let env = build_envelope(
            &test_runtime(),
            &test_row(event_id, "plain body", Some(html)),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read_half, mut write_half) = stream.into_split();
            let mut reader = BufReader::new(read_half);
            write_half.write_all(b"220 fake\r\n").await.unwrap();
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            write_half.write_all(b"250 OK\r\n").await.unwrap();
            line.clear();
            reader.read_line(&mut line).await.unwrap();
            write_half.write_all(b"250 OK\r\n").await.unwrap();
            line.clear();
            reader.read_line(&mut line).await.unwrap();
            write_half.write_all(b"250 OK\r\n").await.unwrap();
            line.clear();
            reader.read_line(&mut line).await.unwrap();
            write_half.write_all(b"354 go\r\n").await.unwrap();
            let mut body = Vec::new();
            loop {
                let mut byte = [0u8; 1];
                reader.read_exact(&mut byte).await.unwrap();
                body.push(byte[0]);
                if body.ends_with(b"\r\n.\r\n") {
                    break;
                }
            }
            write_half.write_all(b"250 OK\r\n").await.unwrap();
            line.clear();
            reader.read_line(&mut line).await.unwrap();
            write_half.write_all(b"221 bye\r\n").await.unwrap();
            body
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let mut session = SmtpSession::open(stream, "vauban-test").await.unwrap();
        session.send(&env).await.unwrap();
        session.quit().await;
        let body = server.await.unwrap();
        let s = std::str::from_utf8(&body).unwrap();
        assert!(s.contains("multipart/related"));
        assert!(s.contains("text/plain"));
        assert!(s.contains("text/html"));
        assert!(s.contains("Content-Type: image/png"));
        let plain_at = s.find("text/plain").expect("plain");
        let html_at = s.find("text/html").expect("html");
        let image_at = s.find("image/png").expect("image");
        assert!(plain_at < html_at);
        assert!(html_at < image_at);
        assert!(s.ends_with("\r\n.\r\n"));
        assert!(s.contains(&format!("--{}--", rel_boundary(event_id))));
    }
}
