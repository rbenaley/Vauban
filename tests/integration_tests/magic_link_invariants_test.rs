//! Source pins for passwordless magic-link auth.

#[test]
fn inv_login_is_email_only_signal_procedure_no_check_email_page() {
    let login = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app/login.rs"));
    assert!(login.contains("Email me a sign-in link"));
    assert!(login.contains("Sending..."));
    assert!(login.contains("/login/magic"));
    assert!(login.contains("#[procedure]"));
    assert!(login.contains("request_login_link"));
    assert!(login.contains("Result<f64>"));
    assert!(login.contains("LOGIN_LINK_UNAVAILABLE"));
    assert!(login.contains("LOGIN_LINK_ACCEPTED"));
    assert!(login.contains("MailCircuitBreaker"));
    assert!(login.contains("mail_circuit.is_open()"));
    assert!(login.contains("let sent = signal(cx"));
    assert!(login.contains("let sending = signal(cx"));
    assert!(login.contains("let unavailable = signal(cx"));
    assert!(login.contains("status > 0.0"));
    assert!(login.contains("vb-eph-tick"));
    assert!(login.contains("Resend in "));
    assert!(login.contains("Use a different email"));
    assert!(login.contains("cooldown_mm_ss"));
    assert!(login.contains("LOGIN_LINK_ERROR"));
    assert!(login.contains("LOGIN_UNAVAILABLE_MESSAGE"));
    assert!(
        login.contains("/login?error=")
            || login.contains("LoginErrorQ") && login.contains("error: LOGIN_LINK_ERROR")
    );
    assert!(login.contains("This sign-in link is invalid or has expired"));
    assert!(login.contains("Sign-in is temporarily unavailable. Please try again later."));
    assert!(login.contains("Delivery can take a few minutes"));
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
fn inv_mail_circuit_wired_in_app_and_mailer() {
    let app = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app.rs"));
    assert!(app.contains("MailCircuitBreaker"));
    assert!(app.contains("router_with_memory_mail_circuit"));
    let mailer = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/mailer.rs"));
    assert!(mailer.contains("record_failure"));
    assert!(mailer.contains("record_success"));
    let circuit = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/mail_circuit.rs"));
    assert!(circuit.contains("allow_attempt"));
    assert!(circuit.contains("force_open"));
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
        assert!(
            contents.contains("purge_interval_minutes = 60"),
            "{rel} must set purge_interval_minutes = 60"
        );
        assert!(
            contents.contains("token_retention_days"),
            "{rel} must set token_retention_days"
        );
        assert!(
            !contents.contains("token_retention_secs"),
            "{rel} must not use token_retention_secs"
        );
        assert!(
            !contents.contains("purge_interval_secs"),
            "{rel} must not use purge_interval_secs"
        );
        assert!(contents.contains("[mail]"), "{rel} must have [mail]");
        assert!(
            contents.contains("[magiclinks]"),
            "{rel} must have [magiclinks]"
        );
    }
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/");
    let default = std::fs::read_to_string(format!("{root}config/default.toml")).unwrap();
    let development = std::fs::read_to_string(format!("{root}config/development.toml")).unwrap();
    let testing = std::fs::read_to_string(format!("{root}config/testing.toml")).unwrap();
    let prod = std::fs::read_to_string(format!("{root}config/vcp.conf")).unwrap();
    assert!(default.contains("token_retention_days = 1"));
    assert!(prod.contains("token_retention_days = 1"));
    assert!(development.contains("token_retention_days = 7"));
    assert!(testing.contains("token_retention_days = 0"));
}

#[test]
fn inv_purge_helpers_and_main_spawn() {
    let magic = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/magic_link.rs"));
    assert!(magic.contains("pub async fn purge_expired_tokens"));
    assert!(magic.contains("pub fn start_magic_link_purge"));
    assert!(magic.contains("pub fn purge_cutoff"));
    let main = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs"));
    assert!(
        main.contains("start_magic_link_purge"),
        "main must spawn the magic-link purge scheduler"
    );
    assert!(
        std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/toasty/migrations/0012_magic_link_tokens_expires_at_index.sql"
        ))
        .exists(),
        "missing expires_at index migration"
    );
}

#[test]
fn inv_cargo_enables_mail_smtp() {
    let cargo = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"));
    assert!(cargo.contains("mail-smtp"));
}
