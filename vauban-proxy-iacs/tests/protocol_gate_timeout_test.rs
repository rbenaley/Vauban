//! Critical pins: classify deadline MUST fire while blocked on `read()`.
//!
//! Runtime behaviour is exercised in `src/protocol_gate.rs` unit tests
//! (`start_paused` + `tokio::time::advance`). This file keeps the
//! production wiring from regressing back to a read-only select.

#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

const GATE: &str = include_str!("../src/protocol_gate.rs");

#[test]
fn need_more_data_select_arms_classify_deadline() {
    assert!(
        GATE.contains("sleep_until"),
        "NeedMoreData select MUST arm sleep_until(deadline) so idle clients \
         cannot bypass CLASSIFY_TIMEOUT"
    );
    assert!(
        GATE.contains("deadline_or_buffer"),
        "deadline expiry MUST map to the deadline_or_buffer unconfirmed cause"
    );
    // Guard against regressing to a read-only select (the pre-0.7.18 bug).
    let need_more = GATE
        .split("ConformityDecision::NeedMoreData")
        .nth(1)
        .and_then(|tail| tail.split("ConformityDecision::").next())
        .expect("NeedMoreData arm must exist");
    assert!(
        need_more.contains("sleep_until"),
        "classify sleep MUST live inside the NeedMoreData arm, not elsewhere"
    );
    assert!(
        need_more.contains("handle.wait_close"),
        "peer close MUST remain wired alongside the deadline sleep"
    );
}

#[test]
fn classify_timeout_is_five_seconds() {
    assert!(
        GATE.contains("Duration::from_secs(5)"),
        "CLASSIFY_TIMEOUT MUST remain a 5 s wall-clock budget (operator runbook)"
    );
}
