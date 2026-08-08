//! Source-shape pins for `smtp_accept_invalid_certs`.

#[test]
fn inv_toml_samples_declare_smtp_accept_invalid_certs() {
    for rel in [
        "config/default.toml",
        "config/development.toml",
        "config/testing.toml",
        "config/vcp.conf",
    ] {
        let path = format!("{}/{rel}", env!("CARGO_MANIFEST_DIR"));
        let body = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
        assert!(
            body.contains("smtp_accept_invalid_certs"),
            "{rel} must declare smtp_accept_invalid_certs"
        );
        assert!(
            !body.contains("smtp_tls_insecure") && !body.contains("smtp_tls_verify"),
            "{rel} must not use smtp_tls_* naming"
        );
    }
}

#[test]
fn inv_mailer_pins_lettre_tls_modes_and_accept_invalid() {
    let mailer = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/mailer.rs"));
    assert!(
        mailer.contains("dangerous_accept_invalid_certs"),
        "mailer must wire lettre dangerous_accept_invalid_certs"
    );
    assert!(
        mailer.contains("Tls::Required") && mailer.contains("Tls::Wrapper"),
        "mailer must set Tls::Required (starttls) and Tls::Wrapper (tls)"
    );
    assert!(
        mailer.contains("ConfiguredSmtpTransport"),
        "mailer must expose ConfiguredSmtpTransport"
    );
    assert!(
        !mailer.contains("smtp_tls_insecure") && !mailer.contains("smtp_tls_verify"),
        "mailer must not use smtp_tls_* naming"
    );
}

#[test]
fn inv_config_rejects_plaintext_plus_accept_invalid() {
    let config = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/config.rs"));
    assert!(
        config.contains("smtp_accept_invalid_certs"),
        "MailConfig must define smtp_accept_invalid_certs"
    );
    assert!(
        config.contains("smtp_accept_invalid_certs requires smtp_encryption=starttls or tls"),
        "validate_mail must reject plaintext + accept_invalid"
    );
}

#[test]
fn inv_runbook_documents_self_signed_smtp_flag() {
    let runbook = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/runbooks/magic_links_smoke_test.md"
    ));
    assert!(runbook.contains("smtp_accept_invalid_certs"));
    assert!(runbook.contains("Self-signed SMTP"));
}
