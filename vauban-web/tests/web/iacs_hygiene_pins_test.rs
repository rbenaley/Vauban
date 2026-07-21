//! Lot G hygiene pins: stale comments and ADR durability.
//!
//! - `OpenTunnelRequest::industrial_protocol` must not claim
//!   "forensic only" (it gates the wire-protocol path).
//! - ADR 001 (recording durability per protocol) must exist and be
//!   linked from Recording Architecture 1.7.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .canonicalize()
        .expect("repo root")
}

#[test]
fn industrial_protocol_comment_mentions_wire_gate_not_forensic_only() {
    let src = include_str!("../../src/ipc/proxy_iacs.rs");
    let start = src
        .find("pub industrial_protocol: String")
        .expect("industrial_protocol field");
    let window = &src[start.saturating_sub(400)..start];
    assert!(
        !window.to_lowercase().contains("forensic only")
            && !window.contains("Currently used only for forensic"),
        "OpenTunnelRequest::industrial_protocol comment must not say \
         forensic-only; it also gates wire protocol"
    );
    assert!(
        window.contains("wire-protocol") || window.contains("wire protocol") || window.contains("ExpectedProfile"),
        "comment must mention the wire-protocol / ExpectedProfile gate"
    );
}

#[test]
fn adr_001_recording_durability_exists() {
    let adr = repo_root().join("docs/adr/001-recording-durability-per-protocol.md");
    assert!(
        adr.is_file(),
        "missing ADR: {}",
        adr.display()
    );
    let body = std::fs::read_to_string(&adr).expect("read ADR");
    assert!(
        body.contains("IACS") && body.contains("ack-block"),
        "ADR must document IACS ack-block decision"
    );
    assert!(
        body.contains("try_send") || body.contains("best-effort"),
        "ADR must document SSH/RDP best-effort + detectable loss"
    );
}

#[test]
fn recording_architecture_1_7_links_adr_001() {
    let doc = repo_root().join("docs/technical/Vauban_Recording_Architecture_EN(1.7).md");
    assert!(doc.is_file(), "Recording 1.7 missing: {}", doc.display());
    let body = std::fs::read_to_string(&doc).expect("read Recording 1.7");
    assert!(
        body.contains("001-recording-durability-per-protocol")
            || body.contains("docs/adr/001"),
        "Recording 1.7 must link ADR 001"
    );
}
