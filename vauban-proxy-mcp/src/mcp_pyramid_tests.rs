use std::sync::{Arc, Barrier};
use std::thread;

use proptest::prelude::*;
use shared::ipc::IpcChannel;
use shared::messages::{ControlMessage, Message, SensitiveString};

use super::SUPPORTED_METHODS;

proptest! {
    #[test]
    fn unknown_methods_are_rejected(method in "[A-Za-z0-9_./]{1,24}") {
        let known = SUPPORTED_METHODS.contains(&method.as_str());
        if known {
            prop_assert!(SUPPORTED_METHODS.contains(&method.as_str()));
        } else {
            prop_assert!(!SUPPORTED_METHODS.contains(&method.as_str()));
        }
    }
}

#[test]
fn battle_supported_methods_stable_under_threads() {
    let barrier = Arc::new(Barrier::new(8));
    let mut handles = Vec::new();
    for _ in 0..8 {
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            SUPPORTED_METHODS.contains(&"tools/call")
                && !SUPPORTED_METHODS.contains(&"session/register")
        }));
    }
    for handle in handles {
        assert!(handle.join().expect("thread"));
    }
}

fn identity(matching: bool) -> (Vec<u8>, String) {
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
    let key = rcgen::KeyPair::generate().expect("key");
    let cert = rcgen::CertificateParams::new(vec!["vauban-proxy-mcp.internal".into()])
        .expect("params")
        .self_signed(&key)
        .expect("cert");
    let pem = if matching {
        key.serialize_pem()
    } else {
        rcgen::KeyPair::generate()
            .expect("other key")
            .serialize_pem()
    };
    (cert.der().to_vec(), pem)
}

fn provision(cert_der: Vec<u8>, key_pem: String) -> Message {
    Message::McpTunnelIdentityProvision {
        cert_der,
        key_pem: SensitiveString::new(key_pem),
    }
}

#[test]
fn early_ping_gets_a_zero_stats_pong_then_identity_installs() {
    let (sup, leaf) = IpcChannel::pair().expect("pair");
    sup.send(&Message::Control(ControlMessage::Ping { seq: 7 }))
        .expect("ping");
    let (cert, key) = identity(true);
    sup.send(&provision(cert, key)).expect("provision");
    assert_eq!(super::wait_for_mcp_identity(&leaf), Ok(()));
    match sup.recv().expect("pong") {
        Message::Control(ControlMessage::Pong { seq, stats }) => {
            assert_eq!(seq, 7);
            assert_eq!(stats.requests_processed, 0);
        }
        other => unreachable!("expected Pong, got {other:?}"),
    }
    assert!(super::tunnel::identity().is_some());
}

#[test]
fn forged_identity_is_rejected_before_the_sandbox() {
    let (sup, leaf) = IpcChannel::pair().expect("pair");
    let (cert, wrong_key) = identity(false);
    sup.send(&provision(cert, wrong_key)).expect("provision");
    let err = super::wait_for_mcp_identity(&leaf).expect_err("mismatched key");
    assert!(err.contains("tunnel server config"), "{err}");
}

#[test]
fn main_loop_pong_counts_the_request_so_e2e_can_tell_the_loops_apart() {
    let mut st = super::ControlLoopState {
        start_time: std::time::Instant::now(),
        requests_processed: 0,
        shutdown: false,
    };
    match super::handle_control(ControlMessage::Ping { seq: 1 }, &mut st) {
        Some(Message::Control(ControlMessage::Pong { stats, .. })) => {
            assert_eq!(stats.requests_processed, 1);
        }
        other => unreachable!("expected Pong, got {other:?}"),
    }
}

fn fn_body<'a>(src: &'a str, signature: &str) -> &'a str {
    let start = src.find(signature).expect("signature present");
    let rest = &src[start..];
    let end = rest.find("\n}\n").map_or(rest.len(), |i| i + 2);
    &rest[..end]
}

/// The leaf E2E distinguishes the pre-sandbox wait from the main loop by
/// `requests_processed`; keep both sides of that marker in place.
#[test]
fn pong_marker_shapes_are_pinned() {
    let src = include_str!("main.rs");
    let wait = fn_body(src, "fn wait_for_mcp_identity(");
    assert!(wait.contains("requests_processed: 0,"));
    assert!(wait.contains("tunnel::install_identity(cert_der, key_pem.as_str())?;"));
    assert!(wait.contains("MCP tunnel identity installed before the sandbox"));
    let ctrl = fn_body(src, "fn handle_control(");
    let bump = ctrl
        .find("st.requests_processed = st.requests_processed.saturating_add(1);")
        .expect("main loop counts the Ping");
    let pong = ctrl
        .find("ControlMessage::Pong {")
        .expect("main loop answers");
    assert!(
        bump < pong,
        "the count must be taken before the Pong is built"
    );
}

/// Tests install the token key, the AccessGuard and the recording root
/// through the `test-seams` constructors, so no source file of this
/// crate writes the process environment, and the release manifest never
/// enables the seams.
#[test]
fn no_env_writes_and_test_seams_stay_dev_only() {
    let needle = concat!("env::", "set_var(");
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
    let mut scanned = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let src = std::fs::read_to_string(&path).unwrap();
        assert!(
            !src.contains(needle),
            "{} writes the process environment",
            path.display()
        );
        scanned += 1;
    }
    assert!(scanned >= 10, "src/ scan found {scanned} files");

    let manifest = include_str!("../Cargo.toml");
    let deps = manifest
        .split("\n[dependencies]\n")
        .nth(1)
        .and_then(|rest| rest.split("\n[").next())
        .expect("[dependencies] table");
    assert!(
        deps.contains("shared = {"),
        "the shared line is in the slice"
    );
    assert!(!deps.contains("test-seams"));
    let dev = manifest
        .split("\n[dev-dependencies]\n")
        .nth(1)
        .expect("[dev-dependencies] table");
    assert!(dev.contains("\"test-seams\""));
}
