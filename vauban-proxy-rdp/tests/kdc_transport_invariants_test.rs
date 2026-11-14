//! Source invariants for the KDC transport seam and the in-process
//! Kerberos harness.
//!
//! The seam (`KdcTransport`) exists so tests can put an in-memory KDC
//! behind the production Kerberos network client. These pins keep it
//! from becoming a second way to reach a KDC in production.

#![allow(clippy::expect_used)]

const MAIN: &str = include_str!("../src/main.rs");
const SESSION: &str = include_str!("../src/session.rs");
const LOOP_TESTS: &str = include_str!("../src/session_credssp_loop_tests.rs");
const MIT_TESTS: &str = include_str!("../src/session_mit_kdc_tests.rs");
const KDC_MOCK: &str = include_str!("../src/test_support/kdc_mock.rs");

fn production() -> &'static str {
    // Everything before the first test-only item of session.rs.
    let end = SESSION
        .find("#[cfg(test)]\n#[path = \"session_credssp_loop_tests.rs\"]")
        .expect("test modules of session.rs");
    &SESSION[..end]
}

/// Production has one path to a KDC: the supervisor relay.
#[test]
fn the_supervisor_relay_is_the_only_production_kdc_transport() {
    let prod = production();
    assert_eq!(
        prod.matches("impl KdcTransport for ").count(),
        1,
        "one production implementation"
    );
    assert!(prod.contains("impl KdcTransport for SupervisorRelay {"));
    // The only place production turns something into a transport is
    // `for_auth_mode`, from the supervisor relay.
    assert_eq!(prod.matches("Arc<dyn KdcTransport>").count(), 2);
    assert!(prod.contains("let relay: Arc<dyn KdcTransport> = relay;"));
    assert!(prod.contains("relay: Option<Arc<SupervisorRelay>>,"));
    // The trait is not exported.
    assert!(prod.contains("\ntrait KdcTransport: Send + Sync {"));
    assert!(!prod.contains("pub trait KdcTransport"));
    assert!(!prod.contains("pub(crate) trait KdcTransport"));
}

/// The harness and the in-memory KDC exist in test builds only.
#[test]
fn the_harness_is_compiled_for_tests_only() {
    assert!(MAIN.contains("#[cfg(test)]\nmod test_support;"));
    assert_eq!(MAIN.matches("mod test_support;").count(), 1);
    for module in ["credssp_loop_tests", "mit_kdc_tests"] {
        let decl = format!("mod {module};");
        let at = SESSION.find(&decl).expect("test module declaration");
        assert!(
            SESSION[..at].ends_with(&format!(
                "#[cfg(test)]\n#[path = \"session_{module}.rs\"]\n"
            )),
            "{module} must be #[cfg(test)]"
        );
    }
    assert!(!production().contains("test_support"));
}

/// The loop tests drive the production function, client and classifier,
/// not copies of them.
#[test]
fn the_loop_tests_drive_production_code() {
    for needle in [
        "perform_credssp_step(",
        "SessionNetworkClient::KerberosRelay(KerberosRelayNetworkClient {",
        "auth_failure_reason(mode, e, &network_client)",
        "build_connector_config(",
    ] {
        assert!(
            LOOP_TESTS.contains(needle),
            "loop tests must use `{needle}`"
        );
    }
    for forbidden in ["CredSspClient::new(", "fn classify("] {
        assert!(
            !LOOP_TESTS.contains(forbidden),
            "loop tests must not rebuild `{forbidden}`"
        );
    }
}

/// The MIT KDC tests are opt-in twice (ignored, and an environment
/// variable), and go through the production relay and descriptor path.
#[test]
fn the_mit_kdc_tests_are_opt_in_and_use_the_real_fd_path() {
    assert_eq!(
        MIT_TESTS.matches("#[tokio::test]").count(),
        MIT_TESTS.matches("#[ignore = ").count(),
        "every MIT KDC test is ignored by default"
    );
    assert_eq!(
        MIT_TESTS.matches("#[tokio::test]").count(),
        MIT_TESTS.matches("    require_opt_in();").count(),
        "every MIT KDC test checks the opt-in variable"
    );
    for needle in [
        "SupervisorRelay::kdc_round_trip(&self.relay, session_id, realm, data)",
        "shared::ipc::send_fd(",
        "shared::recording_fd::recv_fd_timed(",
        "relay.complete(request_id, received).await;",
    ] {
        assert!(MIT_TESTS.contains(needle), "missing `{needle}`");
    }
}

/// The ported KDC keeps its origin and license notice.
#[test]
fn the_ported_kdc_states_its_origin() {
    let header = &KDC_MOCK[..1500];
    assert!(header.contains("Ported from the test suite of `sspi` 0.21.3"));
    assert!(header.contains("MIT OR Apache-2.0"));
    assert!(header.contains("docs/THIRD_PARTY_LICENSES.md"));
    let licenses = include_str!("../../docs/THIRD_PARTY_LICENSES.md");
    assert!(licenses.contains("## sspi test helper (MIT)"));
    assert!(licenses.contains("vauban-proxy-rdp/src/test_support/kdc_mock.rs"));
}
