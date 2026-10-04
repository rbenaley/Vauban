//! Boot-order pins for the MCP tunnel identity (0.9.46).
//!
//! The leaf blocks before its sandbox until `McpTunnelIdentityProvision`
//! arrives (`wait_for_mcp_identity`), and the supervisor's first
//! heartbeat comes from `watchdog_loop`. Pipes are FIFO, so if every
//! spawn path sends the identity before control returns to the
//! watchdog, the identity always precedes the first Ping and so the
//! first Pong. The runtime half of this contract is
//! `e2e_identity_reaches_the_leaf_before_the_first_ping` in `main.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use shared::ipc::IpcChannel;
use shared::messages::{ControlMessage, Message};

const SUPERVISOR_MAIN: &str = include_str!("../src/main.rs");
const LEAF_MAIN: &str = include_str!("../../vauban-proxy-mcp/src/main.rs");

fn prod(src: &str) -> &str {
    src.split("#[cfg(test)]").next().expect("production source")
}

fn fn_body<'a>(src: &'a str, signature: &str) -> &'a str {
    let start = src
        .find(signature)
        .unwrap_or_else(|| panic!("`{signature}` must exist"));
    let rest = &src[start..];
    let end = rest[1..].find("\nfn ").map_or(rest.len(), |i| i + 1);
    &rest[..end]
}

#[test]
fn boot_sends_the_identity_before_the_watchdog_starts() {
    let run = fn_body(prod(SUPERVISOR_MAIN), "fn run_supervisor(");
    let identity = run
        .find("send_mcp_tunnel_identity(")
        .expect("boot must provision the identity");
    let watchdog = run
        .find("watchdog_loop(")
        .expect("boot must start the watchdog");
    assert!(
        identity < watchdog,
        "the identity must be sent before watchdog_loop issues the first Ping"
    );
}

#[test]
fn every_respawn_path_resends_the_identity() {
    for sig in ["fn respawn_service(", "fn respawn_linked_group("] {
        let body = fn_body(prod(SUPERVISOR_MAIN), sig);
        assert!(
            body.contains("send_mcp_tunnel_identity(proxy, web, &config.server.tls.cert_path)"),
            "{sig} must push the identity from the same cert path"
        );
    }
}

#[test]
fn first_ping_is_only_sent_by_the_watchdog() {
    let src = prod(SUPERVISOR_MAIN);
    let pings = src.matches("ControlMessage::Ping {").count();
    assert_eq!(pings, 1, "one heartbeat sender, inside the watchdog path");
    let run = fn_body(src, "fn run_supervisor(");
    assert!(!run.contains("ControlMessage::Ping {"));
}

#[test]
fn leaf_waits_for_the_identity_before_its_sandbox() {
    let main = fn_body(LEAF_MAIN, "async fn main(");
    let wait = main
        .find("wait_for_mcp_identity(channel)")
        .expect("leaf waits for the identity");
    let seal = main
        .find("capsicum::setup_service_sandbox_with_listeners(")
        .expect("leaf seals its sandbox");
    assert!(wait < seal, "identity must be installed before the sandbox");
    let control = main
        .find("handle_control(")
        .or_else(|| main.find("control_loop"))
        .unwrap_or(main.len());
    assert!(
        wait < control,
        "identity must be installed before the control loop"
    );
    let body = fn_body(LEAF_MAIN, "fn wait_for_mcp_identity(");
    assert!(body.contains("tunnel::install_identity("));
    assert!(
        body.contains("ControlMessage::Pong"),
        "early heartbeats are answered so the wait cannot stall the parent"
    );
}

/// The FIFO property the pins rely on, on a real pipe pair: messages
/// written identity-then-Ping are read identity-then-Ping, even under
/// a burst of heartbeats.
#[test]
fn battle_identity_then_pings_keep_their_order() {
    let (sup, leaf) = IpcChannel::pair().unwrap();
    let reader = std::thread::spawn(move || {
        let mut seen = Vec::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while seen.len() < 33 && std::time::Instant::now() < deadline {
            match leaf.try_recv() {
                Ok(m) => seen.push(m),
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(1)),
            }
        }
        seen
    });
    sup.send(&Message::McpTunnelIdentityProvision {
        cert_der: vec![0x30; 512],
        key_pem: shared::messages::SensitiveString::new("k".into()),
    })
    .unwrap();
    for seq in 0..32 {
        sup.send(&Message::Control(ControlMessage::Ping { seq }))
            .unwrap();
    }
    let seen = reader.join().unwrap();
    assert_eq!(seen.len(), 33);
    assert!(matches!(
        seen[0],
        Message::McpTunnelIdentityProvision { .. }
    ));
    for (i, m) in seen[1..].iter().enumerate() {
        assert!(matches!(m, Message::Control(ControlMessage::Ping { seq }) if *seq == i as u64));
    }
}
