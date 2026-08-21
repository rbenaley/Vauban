//! Source-shape invariants for issue notification mail.

use std::process::Command;

#[test]
fn inv_check_issue_notify_script() {
    let output = Command::new("bash")
        .arg("scripts/check_issue_notify.sh")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run check_issue_notify.sh");
    assert!(
        output.status.success(),
        "scripts/check_issue_notify.sh failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn inv_config_pins_notify_block() {
    for rel in [
        "config/vcp.conf",
        "config/default.toml",
        "config/development.toml",
        "config/testing.toml",
    ] {
        let body = std::fs::read_to_string(format!("{}/{}", env!("CARGO_MANIFEST_DIR"), rel))
            .unwrap_or_else(|e| panic!("read {rel}: {e}"));
        assert!(body.contains("[issues.notify]"), "{rel} [issues.notify]");
        assert!(body.contains("exclude_actor"), "{rel} exclude_actor");
        assert!(body.contains("support_comment"), "{rel} support_comment");
        assert!(body.contains("drain_interval_secs"), "{rel} drain");
    }
}

#[test]
fn inv_hooks_enqueue_and_skip_seed() {
    let org_list = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/issues.rs"
    ));
    let org_detail = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/issues/issue_key.rs"
    ));
    let admin_detail = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/issues/issue_key.rs"
    ));
    let fsm = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/issue_status.rs"));
    let db = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/db.rs"));
    let main = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs"));
    let notify = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/issue_notify.rs"));
    assert!(org_list.contains("enqueue_issue_notify"));
    assert!(org_detail.contains("enqueue_issue_notify"));
    assert!(admin_detail.contains("enqueue_issue_notify"));
    assert!(fsm.contains("enqueue_issue_notify"));
    assert!(fsm.contains("NotifyEvent::Status"));
    assert!(fsm.contains("AdvanceOutcome::Applied"));
    assert!(!db.contains("enqueue_issue_notify"));
    assert!(main.contains("start_issue_notify_drain"));
    assert!(!notify.contains("User::all().exec"));
    assert!(notify.contains("upsert_by_issue_id_and_event_and_source_id_and_recipient_user_id"));
}

#[test]
fn inv_outbox_migration_and_template() {
    let sql = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/toasty/migrations/0018_issue_mail_outbox.sql"
    ));
    assert!(sql.contains("CREATE TABLE \"issue_mail_outbox\""));
    assert!(sql.contains("recipient_user_id"));
    assert!(sql.contains("UNIQUE INDEX"));
    let html = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/email/issue-event.html"
    ));
    assert!(html.contains("__ISSUE_KEY__"));
    assert!(html.contains("__ISSUE_URL__"));
    assert!(html.contains("cid:vauban-logo"));
}
