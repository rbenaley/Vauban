//! Source invariants for the classified NLA failure (`RdpAuthFailure`).
//!
//! Behavioral coverage lives in `src/auth_failure.rs` unit and property
//! tests (the binary crate has no `lib` target). This file pins where the
//! reason is computed and what leaves the process with it.

#![allow(clippy::expect_used)]

const MAIN: &str = include_str!("../src/main.rs");
const SESSION: &str = include_str!("../src/session.rs");
const AUTH_FAILURE: &str = include_str!("../src/auth_failure.rs");
const ERROR: &str = include_str!("../src/error.rs");

fn production(source: &'static str) -> &'static str {
    let end = source.find("#[cfg(test)]\nmod tests").expect("test module");
    &source[..end]
}

/// An authentication failure is answered with the reason, never with the
/// error text: `e.to_string()` can quote the KDC or the target.
#[test]
fn an_authentication_failure_leaves_as_a_reason_only() {
    let main = production(MAIN);
    let branch = main
        .find("if let Some(reason) = e.auth_failure() {")
        .expect("auth failure branch");
    let block = &main[branch..];
    let end = block.find("return;").expect("the branch returns");
    let block = &block[..end];
    assert!(block.contains("Message::RdpSessionOpenFailed {"));
    assert!(
        !block.contains("Message::RdpSessionOpened {"),
        "the reason branch must not also send the text-carrying message"
    );
    // The text is logged, in this process.
    assert!(block.contains("error = ?e.to_string(),"));
    assert!(
        !block.contains("error = %e"),
        "the text is logged in its Debug form: it can quote the KDC or the target"
    );
    // The branch comes before the generic answer that carries the text.
    let generic = main[branch..]
        .find("error: Some(e.to_string()),")
        .expect("generic failure answer");
    assert!(end < generic);
}

/// Exactly two producers of the failure message: the session-open gate
/// (NTLM policy and pre-flight) and the session creation.
#[test]
fn the_failure_message_has_two_producers() {
    assert_eq!(
        production(MAIN)
            .matches("Message::RdpSessionOpenFailed {")
            .count(),
        2
    );
}

/// The reason is computed in one place, from typed evidence.
#[test]
fn the_reason_is_computed_once_from_typed_evidence() {
    let session = production(SESSION);
    assert_eq!(
        session.matches("crate::auth_failure::classify(").count(),
        1,
        "one classification site"
    );
    let call = session
        .find("crate::auth_failure::classify(")
        .expect("classify call");
    let args = &session[call..call + 260];
    assert!(args.contains("auth_mode,"));
    assert!(args.contains("&nla_failure_of(error),"));
    assert!(args.contains("&network_client.kdc_trace(),"));
    // `connect` asks that one helper, with the session's mode and client.
    assert_eq!(
        session
            .matches("auth_failure_reason(config.auth_mode, &e, &network_client)")
            .count(),
        1
    );
    // `nla_failure_of` reads kinds and codes, not text.
    let start = session
        .find("fn nla_failure_of(error: &ConnectorError)")
        .expect("nla_failure_of");
    let body = &session[start..start + session[start..].find("\n}\n").expect("end")];
    for forbidden in ["to_string()", "format!(", ".description", "contains("] {
        assert!(
            !body.contains(forbidden),
            "nla_failure_of reads `{forbidden}`"
        );
    }
}

/// The classifier holds no string evidence: the trace and the failure are
/// numbers, flags and closed enums.
#[test]
fn the_classifier_evidence_holds_no_text() {
    let prod = production(AUTH_FAILURE);
    for name in ["pub struct KdcTrace {", "pub struct NlaFailure {"] {
        let start = prod.find(name).expect(name);
        let body = &prod[start..start + prod[start..].find("\n}\n").expect("end")];
        for forbidden in ["String", "Vec<", "&str", "Box<"] {
            assert!(!body.contains(forbidden), "{name} holds `{forbidden}`");
        }
    }
    assert!(
        prod.contains("#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]\npub struct KdcTrace")
    );
}

/// The KDC reply is recorded where it is received, and only its
/// classification is kept.
#[test]
fn the_relay_records_every_exchange_outcome() {
    let session = production(SESSION);
    assert_eq!(
        session.matches("self.trace.record_reply(&reply);").count(),
        1
    );
    assert_eq!(
        session
            .matches("self.trace.record_relay_error(&e);")
            .count(),
        1
    );
}

/// The reason travels in the error type, not in its text.
#[test]
fn the_session_error_carries_the_reason_as_a_field() {
    assert!(
        ERROR.contains("AuthenticationFailed {\n        reason: shared::messages::RdpAuthFailure,")
    );
    assert!(
        ERROR.contains(
            "pub const fn auth_failure(&self) -> Option<shared::messages::RdpAuthFailure>"
        )
    );
}

/// The session-open gate, which applies the NTLM policy first, precedes
/// the pinned-certificate check, the credentials and the session task.
#[test]
fn the_ntlm_policy_gate_precedes_any_session_work() {
    let main = production(MAIN);
    let gate = main
        .find("session::session_open_gate(")
        .expect("session-open gate");
    assert_eq!(main.matches("ntlm_policy(),").count(), 1);
    assert!(
        !main.contains(".permits("),
        "the handler asks the gate, it does not evaluate the policy itself"
    );
    for later in [
        "let expected_cert_fingerprint = match expected_cert_fingerprint {",
        "vault::materialise_rdp_password(",
        "let config = SessionConfig {",
        "tokio::spawn(async move {\n                // SECURITY: Defense-in-depth RBAC re-check",
    ] {
        let at = main.find(later).expect(later);
        assert!(gate < at, "the gate precedes `{later}`");
    }
}

/// The policy comes from the supervisor-provided environment, a value
/// that is not canonical stops the proxy, and the unset state denies.
#[test]
fn the_ntlm_policy_is_read_once_and_fails_closed() {
    let main = production(MAIN);
    assert!(main.contains("std::env::var_os(NtlmPolicy::ENV)"));
    assert!(main.contains("NtlmPolicy::from_env_value("));
    assert!(
        main.contains(
            ".map_err(|e| anyhow::anyhow!(e))?;\n    let _ = NTLM_POLICY.set(ntlm_policy);"
        )
    );
    assert!(main.contains("std::env::remove_var(NtlmPolicy::ENV);"));
    // Absent is handed to the same reader, which refuses it.
    assert!(main.contains("None => NtlmPolicy::from_env_value(None),"));
    assert!(main.contains("NTLM_POLICY.get().copied().unwrap_or(NtlmPolicy::Deny)"));
    assert_eq!(main.matches("NTLM_POLICY.set(").count(), 1, "set once");
}

/// `connect` checks the negotiation outcome right after the X.224
/// exchange and before the TLS upgrade; the CredSSP step strips the
/// Client Info password in Restricted Admin.
#[test]
fn the_negotiation_is_checked_before_tls_and_the_password_is_stripped() {
    let session = production(SESSION);
    let begin = session
        .find("connect_begin_with_nego_flags(&mut framed, &mut connector, extra_nego_flags)")
        .expect("negotiation");
    let check = session
        .find("check_negotiation(config.auth_mode, negotiation)")
        .expect("negotiation check");
    let tls = session
        .find("tls_connector.connect(server_name.clone(), tcp_stream)")
        .expect("TLS upgrade");
    assert!(begin < check && check < tls);
    assert_eq!(
        session
            .matches("check_negotiation(config.auth_mode,")
            .count(),
        1
    );

    let step = session
        .find("async fn perform_credssp_step<S, N>(")
        .expect("perform_credssp_step");
    let body = &session[step..];
    let init = body.find("LocalCredsspSequence::init(").expect("init");
    let strip = body
        .find("strip_client_info_password(&mut connector.config);")
        .expect("strip");
    let first_io = body
        .find("network_client.send(&request)")
        .expect("first I/O");
    assert!(init < strip && strip < first_io, "stripped before any I/O");
}
