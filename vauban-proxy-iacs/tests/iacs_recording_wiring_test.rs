//! Structural pins for IACS PCAP recording wiring in vauban-proxy-iacs.

const MAIN_RS: &str = include_str!("../src/main.rs");
const SERVER_RS: &str = include_str!("../src/server.rs");
const RELAY_RS: &str = include_str!("../src/relay.rs");

#[test]
fn proxy_does_not_drop_audit_channel() {
    assert!(
        !MAIN_RS.contains("drop(audit_channel)"),
        "audit IPC must remain wired when recording is enabled"
    );
}

#[test]
fn relay_exposes_copy_with_counter_and_record() {
    assert!(
        RELAY_RS.contains("copy_with_counter_and_record"),
        "relay must tee bytes to audit before forward"
    );
}

#[test]
fn server_assigns_channel_id_and_lifecycle() {
    assert!(
        SERVER_RS.contains("channel_counter"),
        "per-login channel_id counter required"
    );
    assert!(
        SERVER_RS.contains("send_channel_start"),
        "channel start must be sent via recording hub"
    );
    assert!(
        SERVER_RS.contains("send_session_end"),
        "session end must be sent on handler drop"
    );
}

#[test]
fn ack_router_module_exists() {
    assert!(
        MAIN_RS.contains("AckRouter"),
        "blocking ack router must be wired in main.rs"
    );
}
