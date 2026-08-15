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
use tokio::time::Instant;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::broker::{answer_control, request_smtp_connect};
use crate::provision::MailerRuntime;
use crate::smtp_client::{MailEnvelope, SmtpError, default_client_config, open_session};
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
    let tls_config = default_client_config();
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
        from: runtime.from_address.clone(),
        to: row.recipient.clone(),
        data,
    }
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
}
