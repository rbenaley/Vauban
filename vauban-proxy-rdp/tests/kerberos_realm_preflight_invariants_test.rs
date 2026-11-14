//! Source invariants for the Kerberos pre-flight (realm + ambient
//! configuration isolation) on the RDP proxy.
//!
//! Behavioral coverage lives in `session.rs` unit tests
//! (`kerberos_preflight_gate`, the binary crate has no `lib` target) and
//! in `shared::kerberos`. This file pins where the gate sits.

#![allow(clippy::expect_used)]

const MAIN: &str = include_str!("../src/main.rs");
const SESSION: &str = include_str!("../src/session.rs");

/// The proxy's session-open gate (NTLM policy, then the Kerberos
/// pre-flight) runs once, in the session-open handler, before the
/// credential envelope is opened and before the session config is built.
/// Its decisions are tested behaviorally in `session::credssp_loop_tests`
/// (`attack_ntlm_session_requested_by_compromised_web_under_deny_is_rejected`,
/// `attack_kerberos_session_without_realm_or_isolation_is_rejected`); this
/// file pins where it is called.
#[test]
fn preflight_runs_before_credentials_and_session_config() {
    assert_eq!(
        MAIN.matches("session::session_open_gate(").count(),
        1,
        "exactly one gate call site"
    );
    assert!(
        !MAIN.contains("session::kerberos_preflight("),
        "the handler goes through the gate, not around it"
    );
    let gate = MAIN.find("session::session_open_gate(").expect("gate call");
    for later in [
        "vault::materialise_rdp_password(",
        "let config = SessionConfig {",
        "let preconnected_fd",
    ] {
        let at = MAIN.find(later).expect(later);
        assert!(gate < at, "the gate must precede `{later}`");
    }
    // The gate is the pre-flight behind the policy.
    let start = SESSION
        .find("pub fn session_open_gate(")
        .expect("session_open_gate");
    let body = &SESSION[start..start + SESSION[start..].find("\n}\n").expect("end")];
    let policy = body
        .find("if !policy.permits(auth_mode) {")
        .expect("policy");
    let preflight = body
        .find("kerberos_preflight(auth_mode, domain, ambient_isolated)")
        .expect("pre-flight");
    assert!(policy < preflight);
}

/// The gate reads the real process environment and the process policy,
/// not constants.
#[test]
fn preflight_is_fed_by_the_process_environment() {
    let gate = MAIN.find("session::session_open_gate(").expect("gate call");
    let call = &MAIN[gate..gate + 220];
    assert!(call.contains("ntlm_policy(),"));
    assert!(call.contains("session::process_ambient_config_is_isolated()"));
    assert!(call.contains("rdp_auth_mode"));
}

/// A refusal answers `RdpSessionOpenFailed` with a classified reason and
/// returns: no session task is spawned, and nothing falls back to NTLM.
#[test]
fn refused_preflight_fails_the_session() {
    let gate = MAIN.find("session::session_open_gate(").expect("gate call");
    let after = &MAIN[gate..];
    let end = after
        .find("// VAU-001: defense-in-depth fail-closed.")
        .expect("code after the gate");
    let block = &after[..end];
    assert!(block.contains("Message::RdpSessionOpenFailed {"));
    assert!(block.contains("reason: refusal.auth_failure(),"));
    assert!(
        !block.contains("Message::RdpSessionOpened {"),
        "a refusal never answers with a success-shaped message"
    );
    assert!(block.contains("return Ok(());"));
    assert!(
        !block.contains("RdpAuthMode::Ntlm"),
        "the refusal path must not switch the mode"
    );
}

/// The gate keys on `uses_kerberos()`, so a future Kerberos mode is
/// covered without touching it, and delegates to the shared allowlist.
#[test]
fn preflight_delegates_to_the_shared_seams() {
    let start = SESSION
        .find("pub fn kerberos_preflight(")
        .expect("kerberos_preflight");
    let body = &SESSION[start..];
    let end = body.find("\n}\n").expect("function end");
    let body = &body[..end];
    assert!(body.contains("auth_mode.uses_kerberos()"));
    assert!(body.contains("shared::kerberos::normalize_realm("));
    assert!(
        !body.contains("to_uppercase") && !body.contains("format!"),
        "the realm is built by shared::kerberos only"
    );
    assert!(SESSION.contains("shared::kerberos::ambient_config_is_isolated("));
}
