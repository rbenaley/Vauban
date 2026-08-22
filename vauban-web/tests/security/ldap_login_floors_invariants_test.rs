//! Source-level invariants for LDAPS login credential length floors.
//!
//! Complements the unit/integration suite: pins the structural contracts
//! (shared floors, dual-service validate-at-load, runtime warn gate) so a
//! regression is caught without a directory or database.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;

use shared::validation::{LDAP_LOGIN_PASSWORD_MIN_FLOOR, LDAP_LOGIN_USERNAME_MIN_FLOOR};
use vauban_web::handlers::auth::LOGIN_CREDS_BELOW_MINS_WARN;

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

/// Absolute floors stay locked at 3 / 12 (product contract for issue #38).
#[test]
fn absolute_floors_are_three_and_twelve() {
    assert_eq!(LDAP_LOGIN_USERNAME_MIN_FLOOR, 3);
    assert_eq!(LDAP_LOGIN_PASSWORD_MIN_FLOOR, 12);
}

/// Web config load must call `auth.ldaps.validate()` (fail-closed boot).
#[test]
fn web_config_load_validates_ldaps_login_mins() {
    let src = read("vauban-web/src/config.rs");
    // Production path: load_with_environment must invoke ldaps.validate().
    assert!(
        src.contains("LDAPS login-form length floors")
            && src.contains(".ldaps")
            && src.contains(".validate()"),
        "Config::load_with_environment must validate [auth.ldaps] login floors"
    );
    assert!(
        src.contains("fn validate(&self) -> Result<(), String>")
            || src.contains("pub fn validate(&self) -> Result<(), String>"),
        "WebLdapConfig must expose validate()"
    );
    assert!(
        src.contains("validate_ldap_login_length_config"),
        "WebLdapConfig::validate must delegate to shared::validation"
    );
}

/// Supervisor LdapConfig::validate must always check login mins (even when disabled).
#[test]
fn supervisor_ldap_validate_always_checks_login_mins() {
    let src = read("vauban-supervisor/src/config.rs");
    assert!(
        src.contains("validate_ldap_login_length_config"),
        "LdapConfig::validate must call shared::validation::validate_ldap_login_length_config"
    );
    assert!(
        src.contains("login_username_min_length") && src.contains("login_password_min_length"),
        "LdapConfig must carry both login_*_min_length fields"
    );
}

/// Login handler must gate on credentials_meet_login_mins and emit the warn.
#[test]
fn login_handler_gates_before_directory_and_warns() {
    let src = read("vauban-web/src/handlers/auth.rs");
    assert!(
        src.contains("credentials_meet_login_mins"),
        "login must use shared::validation::credentials_meet_login_mins"
    );
    assert!(
        src.contains(LOGIN_CREDS_BELOW_MINS_WARN),
        "login must emit the canonical below-mins warn literal"
    );
    assert!(
        src.contains("reason = LOGIN_CREDS_BELOW_MINS_WARN"),
        "warn! must attach reason = LOGIN_CREDS_BELOW_MINS_WARN"
    );
    // Compile-time validator length floors must not return on LoginRequest.
    let login_struct = src
        .split("pub struct LoginRequest")
        .nth(1)
        .and_then(|s| s.split("impl std::fmt::Debug for LoginRequest").next())
        .expect("LoginRequest struct body");
    assert!(
        !login_struct.contains("validate(length"),
        "LoginRequest must not use #[validate(length(...))] anymore"
    );
}

/// Shipped TOMLs document both knobs with the absolute floor defaults.
#[test]
fn shipped_tomls_document_login_mins_at_floors() {
    for rel in [
        "config/vauban.conf",
        "config/default.toml",
        "config/development.toml",
    ] {
        let body = read(rel);
        assert!(
            body.contains("login_username_min_length = 3"),
            "{rel} must set login_username_min_length = 3"
        );
        assert!(
            body.contains("login_password_min_length = 12"),
            "{rel} must set login_password_min_length = 12"
        );
    }
}

/// Shared floor constants are the single source of truth for serde defaults.
#[test]
fn web_and_supervisor_defaults_reference_shared_floors() {
    let web = read("vauban-web/src/config.rs");
    let sup = read("vauban-supervisor/src/config.rs");
    assert!(
        web.contains("LDAP_LOGIN_USERNAME_MIN_FLOOR")
            && web.contains("LDAP_LOGIN_PASSWORD_MIN_FLOOR"),
        "web defaults must reference shared floor constants"
    );
    assert!(
        sup.contains("LDAP_LOGIN_USERNAME_MIN_FLOOR")
            && sup.contains("LDAP_LOGIN_PASSWORD_MIN_FLOOR"),
        "supervisor defaults must reference shared floor constants"
    );
}

/// Production configs never enable plaintext `ldap://` as the live URL.
#[test]
fn shipped_configs_do_not_set_plaintext_ldap_url() {
    for rel in [
        "config/vauban.conf",
        "config/default.toml",
        "config/development.toml",
    ] {
        let body = read(rel);
        for line in body.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('#') || trimmed.starts_with("//") {
                continue;
            }
            assert!(
                !trimmed.contains("url = \"ldap://"),
                "{rel} must not assign a plaintext ldap:// url (got {trimmed})"
            );
        }
    }
}

/// `dn_template` is a bind name template, not a filesystem path.
#[test]
fn dn_template_is_not_used_as_a_filesystem_path() {
    let sup = read("vauban-supervisor/src/config.rs");
    assert!(
        sup.contains("std::fs::read(&self.mapping_path)"),
        "aggregation file is read from mapping_path"
    );
    assert!(
        !sup.contains("fs::read(&self.dn_template)")
            && !sup.contains("fs::read_to_string(&self.dn_template)"),
        "dn_template must not be opened as a path"
    );
    let main = read("vauban-supervisor/src/main.rs");
    assert!(
        !main.contains("fs::read(&ldap.dn_template)")
            && !main.contains("fs::read_to_string(&ldap.dn_template)"),
        "supervisor provision must not treat dn_template as a path"
    );
}
