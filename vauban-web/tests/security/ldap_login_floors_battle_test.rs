//! Battle-tested source pins for LDAPS login credential length floors.
//!
//! High-signal regressions from issue #38: short typed credentials must never
//! look like a silent directory failure, and boot must refuse illegal mins.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| {
        panic!("failed to read {rel}: {e}");
    })
}

#[test]
fn battle_warn_message_mentions_ldaps_bind_not_attempted() {
    let auth = read("vauban-web/src/handlers/auth.rs");
    assert!(
        auth.contains("LDAPS bind not attempted"),
        "ops warn must explicitly say LDAPS bind was not attempted"
    );
    assert!(
        auth.contains("login credentials below configured minimums"),
        "ops warn must mention configured minimums"
    );
}

#[test]
fn battle_both_services_refuse_mins_below_floors_at_validate() {
    let web = read("vauban-web/src/config.rs");
    let sup = read("vauban-supervisor/src/config.rs");
    assert!(
        web.contains("validate_ldap_login_length_config"),
        "web must call validate_ldap_login_length_config"
    );
    assert!(
        sup.contains("validate_ldap_login_length_config"),
        "supervisor must call validate_ldap_login_length_config"
    );
}

#[test]
fn battle_supervisor_validate_runs_even_when_ldaps_disabled() {
    let src = read("vauban-supervisor/src/config.rs");
    // Anchor on the LdapConfig impl block so we don't match SecurityConfig::validate etc.
    let ldap_impl = src.find("impl LdapConfig {").expect("impl LdapConfig");
    let ldap_body = &src[ldap_impl..];
    let validate_fn = ldap_body
        .find("pub fn validate(&self) -> Result<()> {")
        .expect("LdapConfig::validate");
    let after_validate = &ldap_body[validate_fn..];
    let mins = after_validate
        .find("validate_ldap_login_length_config")
        .expect("validate_ldap_login_length_config inside LdapConfig::validate");
    let enabled_early = after_validate
        .find("if !self.enabled")
        .expect("enabled early-return in LdapConfig::validate");
    assert!(
        mins < enabled_early,
        "login mins validation must run before the enabled==false early return \
         (mins={mins}, enabled_early={enabled_early})"
    );
}

#[test]
fn battle_architecture_doc_documents_floors_vs_local_policy() {
    let doc = read("docs/technical/Vauban_LDAPS_Auth_Architecture_EN(1.1).md");
    assert!(
        doc.contains("login_username_min_length") && doc.contains("login_password_min_length"),
        "LDAPS architecture doc must document the login_*_min_length knobs"
    );
    assert!(
        doc.contains("security.password_min_length"),
        "doc must distinguish login floors from security.password_min_length"
    );
    assert!(
        doc.contains("LDAPS bind not attempted") || doc.contains("below configured minimums"),
        "doc must mention the below-mins / bind-skipped ops signal"
    );
}

#[test]
fn battle_development_toml_carries_full_ldaps_block_like_vauban_conf() {
    let dev = read("config/development.toml");
    let prod = read("config/vauban.conf");
    for key in [
        "url",
        "dn_template",
        "ca_cert_file",
        "timeout_secs",
        "order",
        "login_username_min_length",
        "login_password_min_length",
    ] {
        assert!(prod.contains(key), "vauban.conf missing {key}");
        assert!(
            dev.contains(key),
            "development.toml must carry the same [auth.ldaps] key as vauban.conf: {key}"
        );
    }
    assert!(
        dev.find("[auth.ldaps]").expect("dev [auth.ldaps]")
            < dev
                .find("[logging]")
                .expect("dev [logging] after argon2/ldaps"),
        "development.toml [auth.ldaps] must sit above [logging] (aligned with vauban.conf)"
    );
}
