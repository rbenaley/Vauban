//! Source pins for passwordless magic-link auth.

#[test]
fn inv_login_is_email_only_signal_procedure_no_check_email_page() {
    let login = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app/login.rs"));
    assert!(login.contains("Email me a sign-in link"));
    assert!(login.contains("/login/magic"));
    assert!(login.contains("#[procedure]"));
    assert!(login.contains("request_login_link"));
    assert!(login.contains("signal sent"));
    assert!(login.contains("vb-eph-tick"));
    assert!(login.contains("Resend in "));
    assert!(login.contains("Use a different email"));
    assert!(login.contains("cooldown_mm_ss"));
    assert!(login.contains("LOGIN_LINK_ERROR"));
    assert!(login.contains("/login?error="));
    assert!(login.contains("This sign-in link is invalid or has expired"));
    assert!(login.contains("post_auth_landing"));
    assert!(login.contains("/choose-org"));
    assert!(!login.contains("/login/check-email"));
    assert!(!login.contains("see_other(\"/login/check-email\")"));
    assert!(!login.contains("name=\"password\""));
    assert!(!login.contains("Seed:"));
    assert!(!login.contains("password_hash"));
    assert!(!login.contains("#[route(POST \"/login\")]"));
}

#[test]
fn inv_issue_token_invalidates_prior_unused() {
    let magic = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/magic_link.rs"));
    let issue_idx = magic
        .find("pub async fn issue_token")
        .expect("issue_token fn");
    let consume_idx = magic
        .find("pub async fn consume_token")
        .expect("consume_token fn");
    assert!(issue_idx < consume_idx);
    let issue_body = &magic[issue_idx..consume_idx];
    assert!(
        issue_body.contains("invalidate_tokens_for_user"),
        "issue_token must invalidate prior unused tokens (single active link)"
    );
}

#[test]
fn inv_app_uses_smtp_not_file_transport() {
    let app = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app.rs"));
    assert!(app.contains("build_smtp_transport"));
    assert!(app.contains("router_with_memory_mail"));
    assert!(!app.contains("FileTransport"));
}

#[test]
fn inv_user_model_has_deleted_at_no_password() {
    let models = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/models/mod.rs"));
    assert!(models.contains("deleted_at"));
    assert!(models.contains("MagicLinkToken"));
    assert!(!models.contains("password_hash"));
}

#[test]
fn inv_toml_magiclinks_ttl_300() {
    for rel in [
        "config/default.toml",
        "config/development.toml",
        "config/testing.toml",
        "config/vcp.conf",
    ] {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/");
        let contents = std::fs::read_to_string(format!("{path}{rel}")).expect(rel);
        assert!(
            contents.contains("token_ttl_secs = 300"),
            "{rel} must set token_ttl_secs = 300"
        );
        assert!(contents.contains("[mail]"), "{rel} must have [mail]");
        assert!(
            contents.contains("[magiclinks]"),
            "{rel} must have [magiclinks]"
        );
    }
}

#[test]
fn inv_cargo_enables_mail_smtp() {
    let cargo = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"));
    assert!(cargo.contains("mail-smtp"));
}
