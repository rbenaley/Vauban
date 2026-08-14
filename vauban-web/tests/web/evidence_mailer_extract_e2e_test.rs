//! E2E / integration pins for evidence + sealed mailer extract.
//!
//! Runtime SMTP delivery needs a live relay (see runbook). These tests
//! pin that web still queues the outbox and that the evidence analyzer
//! remains the Inspect implementation, without requiring outbound SMTP.

use std::sync::Arc;

use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use serial_test::serial;
use tokio::sync::Notify;
use uuid::Uuid;

use vauban_web::schema::email_outbox::dsl;
use vauban_web::services::mailer::{
    AccessRequestApprovedEvent, EmailEvent, EmailRecipient, Mailer, deterministic_event_id,
};

use crate::common::{TestApp, test_db};

#[tokio::test]
#[serial]
async fn e2e_mailer_queue_still_inserts_outbox_from_web() {
    let app = TestApp::spawn().await;
    let mailer = Mailer::new(Arc::new(Notify::new()), true, 5);
    let recipient = "alice@example.test";
    let unique_key = format!("em-e2e-{}", Uuid::new_v4().simple());
    let event = EmailEvent::AccessRequestApproved(AccessRequestApprovedEvent {
        event_id: deterministic_event_id("access_request.approved", &unique_key, recipient),
        recipient: EmailRecipient::bare(recipient),
        asset_name: "prod-db-01".into(),
        protocol: "ssh".into(),
        approver_username: "admin".into(),
        session_url: "https://vauban.test/sessions/approvals/x".into(),
        valid_until: None,
        base_url: "https://vauban.test".into(),
        from_brand: "Vauban PAM".into(),
    });
    let event_id = event.event_id();

    let mut conn = app.get_conn().await;
    mailer.queue(&mut conn, &event).await.expect("queue");

    let status: String = dsl::email_outbox
        .filter(dsl::event_id.eq(event_id))
        .select(dsl::status)
        .first(&mut conn)
        .await
        .expect("outbox row");
    assert_eq!(status, "pending");

    test_db::cleanup(&mut conn).await;
}

#[tokio::test]
#[serial]
async fn e2e_inspect_analyzer_reachable_via_web_reexport() {
    use shared::iacs_protocol::ExpectedProfile;
    use vauban_web::services::iacs_packet_analyzer::analyze_channel_bytes;

    let empty = analyze_channel_bytes(&[], ExpectedProfile::Passthrough);
    assert!(
        empty.is_err(),
        "empty buffer must fail parse (analyzer wired)"
    );
}

/// Staging FreeBSD 2026-08-14 regression: mailer crash-looped because
/// `fd_passing_socket` was declared as both IpcPipe and FdReceiver.
///
/// The buggy profile must fail in `enter_sandbox` at the portable
/// `validate()` step (before any kernel Capsicum/Landlock call). The
/// corrected profile must match `MAILER_KINDS` -- we deliberately do
/// NOT call `enter_sandbox` on the success path here: a successful
/// seal is irreversible and would confine the whole `integration_tests`
/// process on FreeBSD/Linux CI.
#[test]
fn e2e_mailer_sandbox_wiring_staging_regression() {
    use shared::sandbox::{SandboxError, SandboxProfile, enter_sandbox, profiles};

    // Historic buggy mailer main: ipc_fds included fd_passing.
    let buggy = SandboxProfile::new()
        .ipc_pipes(&[10, 11, 12])
        .fd_receiver(12);
    let err = enter_sandbox(buggy).expect_err("buggy mailer wiring must fail-closed");
    assert!(
        matches!(
            err,
            SandboxError::ConflictingFdRights {
                fd: 12,
                first: profiles::ResourceKind::IpcPipe,
                second: profiles::ResourceKind::FdReceiver,
            }
        ),
        "expected ConflictingFdRights, got {err:?}"
    );

    // Corrected wiring (0.9.36+): ipc pipes distinct from fd_receiver.
    let corrected = SandboxProfile::new().ipc_pipes(&[10, 11]).fd_receiver(12);
    let mut kinds = corrected.kinds();
    kinds.dedup();
    let mut expected = profiles::MAILER_KINDS.to_vec();
    expected.sort_unstable();
    expected.dedup();
    assert_eq!(kinds, expected);
}

/// Staging FreeBSD 2026-08-14: after the FD-kind fix, mailer sealed then
/// built the deadpool *after* cap_enter, so every drain tick logged
/// `error connecting to server`. Boot order must be provision -> runtime
/// -> force_create -> seal -> dispatcher_loop. Do not enter_sandbox here.
#[test]
fn e2e_mailer_db_warmup_order_staging_regression() {
    let main = include_str!("../../../vauban-mailer/src/main.rs");
    let body_start = main.find("fn run_service()").expect("run_service");
    let body = &main[body_start..];
    let steps = [
        "wait_for_mailer_provision",
        "tokio::runtime::Builder",
        "force_create_all_connections",
        "setup_service_sandbox_extended",
        "dispatcher_loop",
    ];
    let mut last = 0;
    for step in steps {
        let pos = body
            .find(step)
            .unwrap_or_else(|| panic!("run_service must contain {step}"));
        assert!(
            pos >= last,
            "{step} must follow previous boot step (staging DB-after-seal regression)"
        );
        last = pos;
    }
}
