//! Structural pin for the SSH/RDP auth keepalive heartbeat wiring in
//! `vauban-components.js`.
//!
//! The server-side contract is covered E2E by
//! [`crate::web::heartbeat_session_keepalive_test`]. This module locks
//! in the FRONT-END half so a future refactor of `vauban-components.js`
//! cannot silently stop pinging `/htmx/empty` (which would re-introduce
//! the "logged out while actively typing in SSH/RDP" bug).
//!
//! These are pure source pins (`include_str!`) -- no browser, mirroring
//! the existing `test_alpine_delete_confirm_store_is_registered` pin.

const JS: &str = include_str!("../../static/js/vauban-components.js");

/// Locate `needle` and return the following `window` characters, so we
/// can assert a specific call site wires the heartbeat.
fn window_after<'a>(src: &'a str, needle: &str, window: usize) -> &'a str {
    let start = src
        .find(needle)
        .unwrap_or_else(|| panic!("expected to find `{needle}` in vauban-components.js"));
    let from = start + needle.len();
    let to = (from + window).min(src.len());
    &src[from..to]
}

/// The shared helper must exist and target the web-zone no-op route
/// (NOT `/api/v1/*`, which is independently disableable).
#[test]
fn heartbeat_helper_is_defined_and_targets_htmx_empty() {
    assert!(
        JS.contains("function vaubanAuthHeartbeat("),
        "vauban-components.js must define the shared vaubanAuthHeartbeat() helper"
    );
    assert!(
        JS.contains("'/htmx/empty'"),
        "the heartbeat must ping the web-zone route /htmx/empty"
    );
    assert!(
        !JS.contains("'/api/v1/") || !JS.contains("vaubanAuthHeartbeat"),
        "the heartbeat must not depend on the API zone (/api/v1)"
    );
    assert!(
        JS.contains("setInterval("),
        "the heartbeat must drive a setInterval timer"
    );
    assert!(
        JS.contains("credentials: 'same-origin'"),
        "the heartbeat fetch must send the auth cookie (same-origin credentials)"
    );
}

/// Both the SSH and the RDP components must instantiate the heartbeat at
/// 60s and tear it down on destroy.
#[test]
fn both_viewers_start_and_stop_the_heartbeat() {
    let starts = JS.matches("vaubanAuthHeartbeat(60000)").count();
    assert!(
        starts >= 2,
        "both the SSH and RDP viewers must create vaubanAuthHeartbeat(60000); found {starts}"
    );

    let stops = JS.matches("_hb.stop()").count();
    assert!(
        stops >= 2,
        "both viewers must stop() the heartbeat in destroy(); found {stops}"
    );
}

/// The SSH activity seam (`term.onData`) must mark activity, so keystrokes
/// in the terminal keep the session alive.
#[test]
fn ssh_terminal_input_marks_activity() {
    let after = window_after(JS, "this.term.onData(function (data) {", 80);
    assert!(
        after.contains("_hb.mark()"),
        "the SSH term.onData seam must call _hb.mark() so keystrokes refresh the token"
    );
}

/// Every RDP user-input handler (keyboard + mouse) must mark activity.
/// `resize`/`capabilities` are intentionally excluded.
#[test]
fn rdp_input_handlers_mark_activity() {
    for handler in [
        "onMouseMove: function (e) {",
        "onMouseDown: function (e) {",
        "onMouseUp: function (e) {",
        "onWheel: function (e) {",
        "onKeyDown: function (e) {",
        "onKeyUp: function (e) {",
    ] {
        let after = window_after(JS, handler, 80);
        assert!(
            after.contains("_hb.mark()"),
            "RDP handler `{handler}` must call _hb.mark() to record user activity"
        );
    }
}
