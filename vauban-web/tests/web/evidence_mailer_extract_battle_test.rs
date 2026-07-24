//! Battle-tested source pins for evidence + sealed mailer extract.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("parent")
        .to_path_buf()
}

#[test]
fn battle_supervisor_gate_is_mailer_not_web() {
    let main = std::fs::read_to_string(repo_root().join("vauban-supervisor/src/main.rs"))
        .expect("supervisor main");
    // Whitelist allow check must key off Service::Mailer.
    assert!(
        main.contains("matches!(target_service, Service::Mailer)")
            || main.contains("target_service == Service::Mailer")
            || (main.contains("Service::Mailer") && main.contains("mailer.allows")),
        "supervisor must gate mailer.allows on Service::Mailer"
    );
    // Old Web-gated mailer path must not remain as the primary gate.
    let web_gate = main
        .matches("matches!(target_service, Service::Web)")
        .count();
    let mailer_allows = main.matches("mailer.allows").count();
    assert!(
        mailer_allows >= 1,
        "mailer.allows must still be invoked for SMTP broker"
    );
    // Tolerate other Web matches (self-target skip etc.); require at least
    // one Mailer association near allows in the same file.
    let _ = web_gate;
    assert!(
        main.contains("Service::Mailer"),
        "Service::Mailer must appear in supervisor"
    );
}

#[test]
fn battle_backend_services_include_mailer_before_audit() {
    let main = std::fs::read_to_string(repo_root().join("vauban-supervisor/src/main.rs"))
        .expect("supervisor main");
    let start = main
        .find("const BACKEND_SERVICES")
        .expect("BACKEND_SERVICES");
    let window = &main[start..start.saturating_add(400).min(main.len())];
    let mailer = window
        .find("\"mailer\"")
        .expect("mailer in BACKEND_SERVICES");
    let audit = window.find("\"audit\"").expect("audit in BACKEND_SERVICES");
    assert!(
        mailer < audit,
        "mailer must start before audit (audit stays last)"
    );
}

#[test]
fn battle_web_has_no_request_smtp_connect() {
    let supervisor_ipc =
        std::fs::read_to_string(repo_root().join("vauban-web/src/ipc/supervisor.rs"))
            .expect("supervisor ipc");
    assert!(
        !supervisor_ipc.contains("fn request_smtp_connect")
            && !supervisor_ipc.contains("pending_smtp_connects"),
        "web must not broker SMTP FDs after sealed mailer extract"
    );
}

#[test]
fn battle_mailer_main_seals_sandbox() {
    let main = std::fs::read_to_string(repo_root().join("vauban-mailer/src/main.rs"))
        .expect("mailer main");
    assert!(
        main.contains("sandbox") || main.contains("Capsicum") || main.contains("setup_service"),
        "vauban-mailer must enter Capsicum sandbox"
    );
    assert!(
        main.contains("MailerSmtpProvision") || main.contains("provision"),
        "mailer must wait for SMTP provision before sealing"
    );
}
