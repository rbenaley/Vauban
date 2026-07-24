//! Source invariants for MFA fail-closed / audit HOL safety.
//!
//! Cheap always-on greps so a refactor cannot silently restore infinite
//! broker waits or move `AuditAck` behind `rotate_segment`.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::PathBuf;
use vauban_audit::{
    SUPERVISOR_BROKER_TIMEOUT_SECS, WEB_CRITICAL_ACK_TIMEOUT_SECS, production_broker_budget_is_safe,
};

fn main_rs() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/main.rs");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn budget_rs() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/mfa_hol_budget.rs");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

#[test]
fn inv_production_broker_budget_fits_under_web_critical_ack() {
    assert!(production_broker_budget_is_safe());
    assert_eq!(SUPERVISOR_BROKER_TIMEOUT_SECS, 2);
    assert_eq!(WEB_CRITICAL_ACK_TIMEOUT_SECS, 5);
    const {
        assert!(SUPERVISOR_BROKER_TIMEOUT_SECS < WEB_CRITICAL_ACK_TIMEOUT_SECS);
    }
}

#[test]
fn inv_main_uses_lib_broker_timeout_constant() {
    let main = main_rs();
    assert!(
        main.contains("SUPERVISOR_BROKER_TIMEOUT_SECS"),
        "main.rs must derive SUPERVISOR_BROKER_TIMEOUT from the lib constant"
    );
    assert!(
        main.contains("Duration::from_secs(SUPERVISOR_BROKER_TIMEOUT_SECS)"),
        "main.rs must not hard-code a divergent broker timeout"
    );
}

#[test]
fn inv_timed_broker_helpers_exist() {
    let main = main_rs();
    for needle in [
        "fn recv_from_supervisor_until",
        "fn recv_fd_timed",
        "fn drain_web_audit_channel",
        "fn request_audit_log_file_from_supervisor",
        "fn request_file_from_supervisor",
        "fn request_unlink_from_supervisor",
    ] {
        assert!(main.contains(needle), "main.rs missing `{needle}`");
    }
}

#[test]
fn inv_all_broker_request_helpers_use_timed_recv() {
    let main = main_rs();
    for fn_name in [
        "fn request_audit_log_file_from_supervisor",
        "fn request_unlink_from_supervisor",
    ] {
        let start = main
            .find(fn_name)
            .unwrap_or_else(|| panic!("{fn_name} missing"));
        let window = &main[start..start.saturating_add(2500).min(main.len())];
        assert!(
            window.contains("recv_from_supervisor_until"),
            "{fn_name} must call recv_from_supervisor_until"
        );
        assert!(
            window.contains("SUPERVISOR_BROKER_TIMEOUT"),
            "{fn_name} must bound the wait with SUPERVISOR_BROKER_TIMEOUT"
        );
    }

    let start = main
        .find("fn request_file_from_supervisor")
        .expect("request_file_from_supervisor missing");
    let window = &main[start..start.saturating_add(1200).min(main.len())];
    assert!(
        window.contains("lease_write_fd("),
        "recording file requests must use the shared FD lease helper"
    );
    assert!(
        window.contains("DEFAULT_BROKER_TIMEOUT"),
        "shared recording FD leases must retain the bounded broker wait"
    );
}

#[test]
fn inv_audit_ack_before_rotate_in_handle_audit_event() {
    let main = main_rs();
    let fn_start = main
        .find("fn handle_audit_event")
        .expect("handle_audit_event");
    let body = &main[fn_start..fn_start.saturating_add(4500).min(main.len())];
    let ack = body.find("Message::AuditAck").expect("AuditAck");
    let rotate = body.find("rotate_segment(").expect("rotate_segment");
    assert!(
        ack < rotate,
        "AuditAck must precede rotate_segment (MFA HOL)"
    );
}

#[test]
fn inv_main_loop_priority_drains_web_channel() {
    let main = main_rs();
    let loop_start = main.find("fn main_loop").expect("main_loop");
    let loop_body = &main[loop_start..loop_start.saturating_add(8000).min(main.len())];
    assert!(
        loop_body.contains("drain_web_audit_channel("),
        "main_loop must priority-drain web AuditEvents"
    );
    // ChannelEnd: drain WORM before broker-open + enqueue (CPU off-thread).
    let iacs = main
        .find("fn handle_iacs_recording_message")
        .expect("handle_iacs");
    let iacs_body = &main[iacs..iacs.saturating_add(6000).min(main.len())];
    assert!(
        !iacs_body.contains("gzip_channel_pcap_on_fds"),
        "handle_iacs_recording_message must not run gzip CPU inline"
    );
    let enqueue = iacs_body
        .find("enqueue_iacs_gzip_job")
        .expect("enqueue_iacs_gzip_job");
    let drain_before = iacs_body[..enqueue]
        .rfind("drain_web_audit_channel")
        .expect("drain before enqueue");
    assert!(
        drain_before < enqueue,
        "IACS ChannelEnd must drain web AuditEvents before gzip enqueue"
    );
}

#[test]
fn inv_budget_module_documents_web_mirror() {
    let budget = budget_rs();
    assert!(budget.contains("CRITICAL_ACK_TIMEOUT"));
    assert!(budget.contains("audit ack timed out") || budget.contains("fail-closed"));
}
