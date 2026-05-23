//! L4 -- protocol gate adversarial / structural pin tests.
//!
//! Runtime coverage lives in `src/protocol_gate.rs` unit tests;
//! this file pins the production wiring and expands the cross-
//! protocol matrix.

#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

const SRC: &str = "src";

fn read_src(rel: &str) -> String {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(SRC)
        .join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {}", p.display(), e))
}

#[test]
fn relay_uses_protocol_gate_on_ews_to_asset_leg() {
    let server = read_src("server.rs");
    assert!(
        server.contains("protocol_gate::filtered_copy_with_counter"),
        "spawn_relay MUST route EWS -> asset bytes through filtered_copy_with_counter"
    );
    assert!(
        server.contains("ExpectedProfile::from_industrial_label"),
        "spawn_relay MUST map PendingTunnel.industrial_protocol to ExpectedProfile"
    );
}

#[test]
fn protocol_gate_module_exports_classifier_constants() {
    let gate = read_src("protocol_gate.rs");
    for needle in [
        "CLASSIFY_MAX_BYTES",
        "CLASSIFY_TIMEOUT",
        "iacs_protocol_mismatch",
        "iacs_protocol_confirmed",
        "iacs_protocol_unconfirmed",
        "log_protocol_unconfirmed",
        "peer_closed",
        "sleep_until",
    ] {
        assert!(
            gate.contains(needle),
            "protocol_gate.rs MUST define/use {needle}"
        );
    }
}

#[test]
fn industrial_protocol_field_is_not_dead_code() {
    let auth = read_src("auth.rs");
    assert!(
        !auth.contains("#[allow(dead_code)]\n    pub industrial_protocol"),
        "PendingTunnel.industrial_protocol MUST be live (drives the gate)"
    );
    assert!(
        auth.contains("pub industrial_protocol: String"),
        "PendingTunnel MUST expose industrial_protocol"
    );
}

#[test]
fn classify_matrix_foreign_modbus_vs_opcua() {
    use shared::iacs_protocol::{
        ConformityDecision, ExpectedProfile, WireProtocol, evaluate_conformity,
    };
    assert_eq!(
        evaluate_conformity(ExpectedProfile::Modbus, WireProtocol::OpcUa, false),
        ConformityDecision::ForeignProtocol
    );
}

#[test]
fn tcp_profile_is_passthrough() {
    use shared::iacs_protocol::{
        ConformityDecision, ExpectedProfile, WireProtocol, evaluate_conformity,
    };
    assert_eq!(
        evaluate_conformity(ExpectedProfile::Passthrough, WireProtocol::Profinet, false),
        ConformityDecision::AllowPassthrough
    );
}
