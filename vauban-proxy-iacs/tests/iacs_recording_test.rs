//! Integration / structural pin tests for vauban-proxy-iacs PCAP
//! recording.
//!
//! The actual `ChannelRecorder::write_batch` ack-timeout path is
//! already covered by the `mod tests` block of
//! `src/iacs_recording.rs` (timer-paused tokio test). The crate is
//! a binary-only target without a public `lib.rs`, so we drive
//! cross-module invariants here with `include_str!` pins (the same
//! pattern used by `iacs_recording_wiring_test.rs` and the
//! `host_key_loaded_before_capsicum_test.rs`).

#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

const SERVER_RS: &str = include_str!("../src/server.rs");
const MAIN_RS: &str = include_str!("../src/main.rs");
const RECORDING_RS: &str = include_str!("../src/iacs_recording.rs");
const PROTOCOL_GATE_RS: &str = include_str!("../src/protocol_gate.rs");

#[test]
fn write_batch_uses_tokio_timeout() {
    assert!(
        RECORDING_RS.contains("tokio::time::timeout(ACK_TIMEOUT"),
        "write_batch MUST cap the ack wait via tokio::time::timeout"
    );
    assert!(
        RECORDING_RS.contains("pub const ACK_TIMEOUT"),
        "ACK_TIMEOUT constant must be exposed for tests / docs"
    );
}

#[test]
fn ack_router_exposes_cancel() {
    assert!(
        RECORDING_RS.contains("pub async fn cancel"),
        "AckRouter::cancel is required to drain stale entries on timeout"
    );
}

#[test]
fn recording_metrics_struct_present_with_atomic_u64() {
    assert!(
        RECORDING_RS.contains("pub struct RecordingMetrics"),
        "metrics struct required so the supervisor can observe recording health"
    );
    assert!(
        RECORDING_RS.contains("pub ack_timeouts: AtomicU64"),
        "RecordingMetrics MUST expose ack_timeouts counter"
    );
}

#[test]
fn channel_endpoints_struct_carries_originator_and_server() {
    assert!(
        RECORDING_RS.contains("pub struct ChannelEndpoints"),
        "ChannelEndpoints must be a public type so server.rs can build it"
    );
    for field in [
        "pub client_ip: String",
        "pub client_port: u16",
        "pub server_ip: String",
        "pub server_port: u16",
    ] {
        assert!(
            RECORDING_RS.contains(field),
            "ChannelEndpoints missing field: {field}"
        );
    }
}

#[test]
fn server_captures_originator_and_propagates_endpoints() {
    assert!(
        SERVER_RS.contains("originator_address: &str"),
        "server.rs::channel_open_direct_tcpip must capture originator_address"
    );
    assert!(
        !SERVER_RS.contains("_originator_address: &str,\n        _originator_port: u32,\n        _session: &mut Session,\n    ) -> Result<bool, Self::Error> {\n        // Acquire"),
        "originator_address/port must NOT be _-prefixed in direct-tcpip"
    );
    assert!(
        SERVER_RS.contains("upstream_stream\n            .peer_addr()"),
        "server.rs must read peer_addr() of the brokered upstream BEFORE into_split"
    );
    assert!(
        SERVER_RS.contains("ChannelEndpoints {"),
        "server.rs must construct ChannelEndpoints to feed send_channel_start"
    );
    assert!(
        SERVER_RS.contains("connected_at_us: Arc<std::sync::atomic::AtomicU64>"),
        "handler must memoize connected_at_us across multiple direct-tcpip channels"
    );
}

#[test]
fn send_channel_start_signature_carries_endpoints_and_anchor() {
    assert!(
        RECORDING_RS.contains("endpoints: ChannelEndpoints"),
        "send_channel_start must accept ChannelEndpoints"
    );
    assert!(
        RECORDING_RS.contains("connected_at_us: u64"),
        "send_channel_start must accept connected_at_us"
    );
    assert!(
        RECORDING_RS.contains("connected_at_us,") && RECORDING_RS.contains("client_ip: endpoints.client_ip"),
        "the IPC message must carry the new fields verbatim"
    );
}

#[test]
fn no_try_send_on_recording_channel() {
    // `try_send` would let the relay overrun a slow audit and
    // silently drop frames -- breaking the durability contract of
    // pcap-bundle recordings.
    let bad_calls: Vec<&str> = RECORDING_RS
        .lines()
        .filter(|l| l.contains(".try_send"))
        .collect();
    assert!(
        bad_calls.is_empty(),
        "iacs_recording must not use try_send (frames could be silently dropped)"
    );
}

#[test]
fn audit_channel_not_dropped_in_main_loop() {
    assert!(
        !MAIN_RS.contains("drop(audit_channel)"),
        "audit IPC must remain wired throughout the lifetime of the proxy"
    );
}

fn capsicum_sandbox_call_idx() -> usize {
    MAIN_RS
        .find("capsicum::setup_service_sandbox")
        .expect("capsicum::setup_service_sandbox call required")
}

#[test]
fn no_tcpconnect_after_capsicum_in_main() {
    let sandbox_idx = capsicum_sandbox_call_idx();
    let post_sandbox = &MAIN_RS[sandbox_idx..];
    assert!(
        !post_sandbox.contains("TcpStream::connect"),
        "no TcpStream::connect may appear after Capsicum sandbox setup"
    );
}

#[test]
fn audit_async_channel_constructed_before_sandbox() {
    // `audit_async` is constructed via `.map(AsyncIpcChannel::new)`
    // on the `audit_channel: Option<IpcChannel>`; the `audit_async`
    // binding line is the canonical anchor.
    let audit_idx = MAIN_RS
        .find("let audit_async = if recording_enabled")
        .expect("audit_async binding required");
    let sandbox_idx = capsicum_sandbox_call_idx();
    assert!(
        audit_idx < sandbox_idx,
        "audit_async MUST be wired BEFORE Capsicum sandbox setup"
    );
}

#[test]
fn protocol_gate_emits_recording_via_recorder() {
    // The protocol gate (Modbus / OPC-UA / S7) is the only path
    // that should drop foreign-protocol traffic. PCAP records
    // emitted on a gated channel MUST go through the
    // ChannelRecorder, not be written ad-hoc.
    assert!(
        PROTOCOL_GATE_RS.contains("recorder"),
        "protocol_gate must accept a ChannelRecorder so gated flows are still recorded once admitted"
    );
}

#[test]
fn handshake_emitted_only_via_synth_module() {
    // Defence in depth: no manual SYN/SYN-ACK byte-twiddling is
    // allowed in the proxy. The synth layer is owned by
    // vauban-audit; the proxy only forwards application bytes.
    assert!(
        !SERVER_RS.contains("TCP_FLAG_SYN") && !RECORDING_RS.contains("TCP_FLAG_SYN"),
        "TCP flag manipulation MUST live exclusively in vauban-audit::iacs_pcap_synth"
    );
}

#[test]
fn clamp_port_handles_oversized_originator() {
    // `originator_port` is `u32` per RFC 4254 §7.2 even though TCP
    // only has 16-bit ports. The proxy clamps oversized values so
    // the synthetic PCAP layer never displays a believable but
    // bogus port number.
    assert!(
        SERVER_RS.contains("fn clamp_port(port: u32) -> u16"),
        "clamp_port helper required"
    );
}
