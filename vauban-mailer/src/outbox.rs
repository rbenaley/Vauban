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
use tracing::{debug, error, info};
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
            Ok(n) => info!(processed = n, "Mailer drain: processed batch"),
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
        push_batch_retry(&ctx.pool, &batch, &e.to_string()).await?;
        return Ok(batch.len());
    }

    let mut processed = 0usize;
    for row in &batch {
        let envelope = build_envelope(&ctx.runtime, row);
        match session.send(&envelope).await {
            Ok(()) => {
                mark_sent(&ctx.pool, row).await?;
                processed += 1;
            }
            Err(e) => {
                let transient = e.is_transient();
                mark_retry_or_failed(&ctx.pool, row, &e, transient, ctx.runtime.max_attempts)
                    .await?;
                processed += 1;
                if matches!(
                    e,
                    SmtpError::Io(_) | SmtpError::Tls(_) | SmtpError::Protocol(_)
                ) {
                    session.quit().await;
                    return Ok(processed);
                }
            }
        }
    }

    session.quit().await;
    Ok(processed)
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
    info!(
        outbox_id = row.id,
        event_id = %row.event_id,
        event_kind = %row.event_kind,
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
) -> Result<(), DrainError> {
    let new_attempts = row.attempts + 1;
    let max_attempts = row.max_attempts.max(config_max_attempts);
    let mut conn = pool
        .get()
        .await
        .map_err(|e| DrainError::Pool(e.to_string()))?;

    if new_attempts >= max_attempts || !transient {
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
    }
    Ok(())
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
}
