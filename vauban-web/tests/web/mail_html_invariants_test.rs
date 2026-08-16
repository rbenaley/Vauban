//! Source-shape pins for branded HTML mail templates.

use vauban_web::services::mail_templates::CATALOGUE;

#[test]
fn catalogue_matches_fourteen_event_kinds() {
    let kinds: Vec<&str> = CATALOGUE.iter().map(|(k, _)| *k).collect();
    assert_eq!(kinds.len(), 14);
    for expected in [
        "access_request.submitted",
        "access_request.approved",
        "access_request.rejected",
        "access_request.revoked",
        "access_request.expired",
        "user.created",
        "user.password_reset_requested",
        "user.locked_after_failed_attempts",
        "user.mfa_reset_by_admin",
        "security.mono_admin_detected",
        "iacs.onboard_submitted",
        "iacs.onboard_approved",
        "iacs.onboard_rejected",
        "iacs.offboarded",
    ] {
        assert!(kinds.contains(&expected), "missing {expected}");
    }
}

#[test]
fn templates_live_under_email_not_askama_templates() {
    let readme = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/email/README.md"));
    assert!(readme.contains("vauban-web/email/"));
    assert!(readme.contains("include_str"));
}

#[test]
fn mailer_rs_no_longer_promises_askama_under_templates_email() {
    let source = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/services/mailer.rs"
    ));
    assert!(!source.contains("Askama"));
    assert!(!source.contains("templates/email/"));
    assert!(source.contains("load_approver_contacts"));
    assert!(!source.contains("per active superuser"));
}
