//! Integration tests for the transactional outbox pattern (Issue #10).
//!
//! These tests do NOT speak SMTP; they exercise:
//!
//! 1. `Mailer::queue` round-trip: insert -> SELECT shows a `pending`
//!    row with the right kind/recipient/subject.
//! 2. Idempotence: queueing the same `event_id` twice surfaces
//!    `MailerError::Duplicate` AND leaves only one row.
//! 3. Atomicity: a failing surrounding transaction discards the
//!    inserted row (the contract `Mailer::queue` advertises).
//! 4. Notify wake-up: a successful queue triggers
//!    `notify.notified()` exactly once.
//! 5. CRLF guard: any `\r`/`\n` in the recipient or subject is
//!    rejected before the INSERT.
//! 6. Disabled mailer is a no-op (no row inserted).
//!
//! The tests run against the same Postgres fixture as the rest of
//! `vauban-web/tests/`. The `email_outbox` table is created by the
//! migration `20260501000000_email_outbox`.

use std::sync::Arc;
use std::time::Duration;

use diesel::prelude::*;
use diesel_async::{AsyncConnection, RunQueryDsl, scoped_futures::ScopedFutureExt};
use tokio::sync::Notify;
use uuid::Uuid;

use vauban_web::db::DbConnection;
use vauban_web::models::email_outbox::OutboxEntry;
use vauban_web::schema::email_outbox::dsl;
use vauban_web::services::mailer::{
    AccessRequestApprovedEvent, EmailEvent, EmailRecipient, Mailer, MailerError,
    deterministic_event_id,
};

use crate::common;

/// Build a fake event with a UNIQUE event_id per test invocation so
/// integration runs are independent of each other (the
/// `email_outbox.event_id` UNIQUE constraint would otherwise resurface
/// rows from a previous run).
fn fake_event(recipient: &str, business_key: &str) -> EmailEvent {
    let unique_key = format!("{}-{}", business_key, Uuid::new_v4().simple());
    EmailEvent::AccessRequestApproved(AccessRequestApprovedEvent {
        event_id: deterministic_event_id("access_request.approved", &unique_key, recipient),
        recipient: EmailRecipient::bare(recipient),
        asset_name: "prod-db-01".into(),
        protocol: "ssh".into(),
        approver_username: "admin".into(),
        session_url: "https://vauban.test/sessions/approvals/x".into(),
        valid_until: None,
        base_url: "https://vauban.test".into(),
        from_brand: "Vauban PAM".into(),
    })
}

async fn count_outbox_rows(conn: &mut DbConnection, event_id: Uuid) -> i64 {
    dsl::email_outbox
        .filter(dsl::event_id.eq(event_id))
        .count()
        .get_result(conn)
        .await
        .expect("count")
}

async fn load_outbox_row(conn: &mut DbConnection, event_id: Uuid) -> Option<OutboxEntry> {
    dsl::email_outbox
        .filter(dsl::event_id.eq(event_id))
        .first::<OutboxEntry>(conn)
        .await
        .ok()
}

#[tokio::test]
async fn queue_inserts_a_pending_row_with_event_metadata() {
    let app = common::TestApp::spawn().await;
    let mailer = Mailer::new(Arc::new(Notify::new()), true, 5);
    let event = fake_event("alice@example.test", "queue-inserts");
    let event_id = event.event_id();

    let mut conn = app.get_conn().await;
    mailer.queue(&mut conn, &event).await.expect("queue");

    let row = load_outbox_row(&mut conn, event_id).await.expect("row");
    assert_eq!(row.event_kind, "access_request.approved");
    assert_eq!(row.recipient, "alice@example.test");
    assert_eq!(row.status, "pending");
    assert_eq!(row.attempts, 0);
    assert!(row.subject.contains("[Vauban]"));
    assert!(row.body_text.contains("ssh"));
    let html = row.body_html.as_deref().expect("html persisted");
    assert!(html.contains("cid:vauban-logo"));
    assert!(html.contains("prod-db-01"));
}

#[tokio::test]
async fn queued_html_round_trips_through_mailer_build_envelope() {
    use secrecy::SecretString;
    use shared::messages::SmtpEncryption;
    use vauban_mailer::outbox::{OutboxEntry as MailerRow, build_envelope};
    use vauban_mailer::provision::MailerRuntime;

    let app = common::TestApp::spawn().await;
    let mailer = Mailer::new(Arc::new(Notify::new()), true, 5);
    let event = fake_event("alice@example.test", "html-envelope");
    let event_id = event.event_id();

    let mut conn = app.get_conn().await;
    mailer.queue(&mut conn, &event).await.expect("queue");
    let row = load_outbox_row(&mut conn, event_id).await.expect("row");

    let runtime = MailerRuntime {
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
    };
    let mailer_row = MailerRow {
        id: row.id,
        event_id: row.event_id,
        event_kind: row.event_kind,
        recipient: row.recipient,
        recipient_name: row.recipient_name,
        subject: row.subject,
        body_text: row.body_text,
        body_html: row.body_html,
        status: row.status,
        attempts: row.attempts,
        max_attempts: row.max_attempts,
        next_retry_at: row.next_retry_at,
        last_error: row.last_error,
        created_at: row.created_at,
        sent_at: row.sent_at,
    };
    let env = build_envelope(&runtime, &mailer_row);
    assert!(env.data.contains("multipart/related"));
    assert!(env.data.contains("Content-ID: <vauban-logo>"));
    assert!(env.data.contains("text/plain"));
    assert!(env.data.contains("text/html"));
    assert!(env.data.contains("image/png"));
    let plain_at = env.data.find("text/plain").expect("plain");
    let html_at = env.data.find("text/html").expect("html");
    let image_at = env.data.find("image/png").expect("image");
    assert!(plain_at < html_at);
    assert!(html_at < image_at);
}

#[tokio::test]
async fn queue_twice_with_same_event_id_returns_duplicate_and_leaves_one_row() {
    let app = common::TestApp::spawn().await;
    let mailer = Mailer::new(Arc::new(Notify::new()), true, 5);
    let event = fake_event("alice@example.test", "queue-twice");
    let event_id = event.event_id();

    let mut conn = app.get_conn().await;
    mailer.queue(&mut conn, &event).await.expect("queue 1");

    let res = mailer.queue(&mut conn, &event).await;
    assert!(matches!(res, Err(MailerError::Duplicate)));

    let n = count_outbox_rows(&mut conn, event_id).await;
    assert_eq!(n, 1, "duplicate must NOT insert a second row");
}

#[tokio::test]
async fn queue_inside_failing_transaction_discards_row() {
    let app = common::TestApp::spawn().await;
    let mailer = Mailer::new(Arc::new(Notify::new()), true, 5);
    let event = fake_event("alice@example.test", "atomicity");
    let event_id = event.event_id();

    let mut conn = app.get_conn().await;

    // Wrap queue() in a transaction that we explicitly roll back.
    // Hold a clone of the mailer across the closure via an Arc-style
    // borrow.
    let mailer_ref = &mailer;
    let event_ref = &event;
    let res: Result<(), diesel::result::Error> = conn
        .transaction::<(), diesel::result::Error, _>(|tx| {
            async move {
                mailer_ref
                    .queue(tx, event_ref)
                    .await
                    .map_err(|_| diesel::result::Error::RollbackTransaction)?;
                // Intentionally fail.
                Err(diesel::result::Error::RollbackTransaction)
            }
            .scope_boxed()
        })
        .await;
    assert!(res.is_err());

    let n = count_outbox_rows(&mut conn, event_id).await;
    assert_eq!(
        n, 0,
        "rollback of the surrounding transaction MUST discard the queued row"
    );
}

#[tokio::test]
async fn queue_notifies_dispatcher_on_success() {
    let app = common::TestApp::spawn().await;
    let notify = Arc::new(Notify::new());
    let mailer = Mailer::new(Arc::clone(&notify), true, 5);
    let event = fake_event("alice@example.test", "notify-on-success");

    let mut conn = app.get_conn().await;
    mailer.queue(&mut conn, &event).await.expect("queue");

    // notified() consumes a permit; we should see it almost
    // immediately. A real dispatcher is parked on .notified() so
    // wake-up is the entire purpose of the call.
    let woke = tokio::time::timeout(Duration::from_millis(200), notify.notified())
        .await
        .is_ok();
    assert!(woke, "Mailer::queue must call notify_one() on success");
}

#[tokio::test]
async fn queue_rejects_crlf_in_recipient_address() {
    let app = common::TestApp::spawn().await;
    let mailer = Mailer::new(Arc::new(Notify::new()), true, 5);

    // Manually bypass the EmailRecipient constructor (which doesn't
    // validate). The Mailer guard MUST catch this.
    let event = EmailEvent::AccessRequestApproved(AccessRequestApprovedEvent {
        event_id: Uuid::new_v4(),
        recipient: EmailRecipient {
            address: "alice\r\nBcc: mallory@evil.test".into(),
            display_name: String::new(),
        },
        asset_name: "x".into(),
        protocol: "ssh".into(),
        approver_username: "admin".into(),
        session_url: "https://vauban.test/x".into(),
        valid_until: None,
        base_url: "https://vauban.test".into(),
        from_brand: "Vauban PAM".into(),
    });
    let mut conn = app.get_conn().await;
    let res = mailer.queue(&mut conn, &event).await;
    assert!(
        matches!(res, Err(MailerError::CrlfInjection(_))),
        "CRLF in recipient address MUST be rejected, got {:?}",
        res
    );
}

#[tokio::test]
async fn queue_rejects_crlf_in_recipient_display_name() {
    let app = common::TestApp::spawn().await;
    let mailer = Mailer::new(Arc::new(Notify::new()), true, 5);
    let event = EmailEvent::AccessRequestApproved(AccessRequestApprovedEvent {
        event_id: Uuid::new_v4(),
        recipient: EmailRecipient {
            address: "alice@example.test".into(),
            display_name: "Alice\nBcc: mallory@evil.test".into(),
        },
        asset_name: "x".into(),
        protocol: "ssh".into(),
        approver_username: "admin".into(),
        session_url: "https://vauban.test/x".into(),
        valid_until: None,
        base_url: "https://vauban.test".into(),
        from_brand: "Vauban PAM".into(),
    });
    let mut conn = app.get_conn().await;
    let res = mailer.queue(&mut conn, &event).await;
    assert!(
        matches!(res, Err(MailerError::CrlfInjection(_))),
        "CRLF in display_name MUST be rejected"
    );
}

#[tokio::test]
async fn queue_rejects_empty_recipient_address() {
    let app = common::TestApp::spawn().await;
    let mailer = Mailer::new(Arc::new(Notify::new()), true, 5);
    let event = EmailEvent::AccessRequestApproved(AccessRequestApprovedEvent {
        event_id: Uuid::new_v4(),
        recipient: EmailRecipient::bare(""),
        asset_name: "x".into(),
        protocol: "ssh".into(),
        approver_username: "admin".into(),
        session_url: "https://vauban.test/x".into(),
        valid_until: None,
        base_url: "https://vauban.test".into(),
        from_brand: "Vauban PAM".into(),
    });
    let mut conn = app.get_conn().await;
    let res = mailer.queue(&mut conn, &event).await;
    assert!(matches!(res, Err(MailerError::EmptyRecipient)));
}

#[tokio::test]
async fn queue_when_disabled_is_a_noop() {
    let app = common::TestApp::spawn().await;
    let mailer = Mailer::new(Arc::new(Notify::new()), false, 5);
    let event = fake_event("alice@example.test", "disabled-noop");
    let event_id = event.event_id();

    let mut conn = app.get_conn().await;
    mailer
        .queue(&mut conn, &event)
        .await
        .expect("queue must succeed silently when disabled");

    let n = count_outbox_rows(&mut conn, event_id).await;
    assert_eq!(n, 0, "disabled mailer MUST NOT insert");
}
