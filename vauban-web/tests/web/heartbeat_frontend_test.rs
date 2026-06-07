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

/// Both viewers must bounce to /login when the server closes the socket
/// with the auth-expiry close code 4401 (login session expired
/// mid-session). This mirrors the HTTP AuthRedirect behaviour.
#[test]
fn viewers_redirect_to_login_on_auth_expiry_close_code() {
    let redirects = JS
        .matches("window.location.href = '/login?reason=session_expired'")
        .count();
    assert!(
        redirects >= 2,
        "both the SSH and RDP onclose handlers must redirect to /login?reason=session_expired on 4401; found {redirects}"
    );
    let guards = JS.matches("event.code === 4401").count();
    assert!(
        guards >= 2,
        "both onclose handlers must gate the /login redirect on event.code === 4401; found {guards}"
    );
}

/// Non-regression: the /login redirect must be triggered ONLY by 4401,
/// never by an admin termination / user-disconnect close (code 1000).
/// Every `window.location.href = '/login'` must be preceded (within the
/// same handler) by a `event.code === 4401` guard, and there must be no
/// `=== 1000` branch driving a /login redirect.
#[test]
fn login_redirect_is_strictly_gated_on_4401_not_1000() {
    // No /login redirect may be reached from a `code === 1000` guard.
    assert!(
        !JS.contains("event.code === 1000"),
        "no onclose handler should branch on code 1000 to redirect; admin \
         termination (1000) must keep the current behaviour (no /login bounce)"
    );

    // Each /login redirect must have a 4401 guard within the preceding
    // window (the `if (event.code === 4401) { window.location.href ...`
    // pattern), proving the redirect is reachable only for 4401.
    let mut cursor = 0usize;
    let needle = "window.location.href = '/login?reason=session_expired'";
    while let Some(rel) = JS[cursor..].find(needle) {
        let abs = cursor + rel;
        let from = abs.saturating_sub(120);
        let preceding = &JS[from..abs];
        assert!(
            preceding.contains("event.code === 4401"),
            "a `{needle}` at offset {abs} is not guarded by `event.code === 4401` \
             within the preceding 120 chars; the redirect must be exclusive to 4401 \
             so admin-terminated (1000) sessions are not bounced to /login"
        );
        cursor = abs + needle.len();
    }
}
