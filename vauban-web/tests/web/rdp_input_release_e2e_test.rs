//! VAUBAN Web - RDP stuck-modifier fix (release-keys) tests.
//!
//! Production bug: the RDP viewer sent raw keydown/keyup events but never
//! handled focus loss. Leaving the canvas with a keyboard shortcut
//! (Cmd+Tab, Alt+Tab, tab switch) swallowed the modifier keyup, so the
//! RDP server believed Shift/Ctrl/Alt/Meta were held forever -- every
//! subsequent keystroke came out uppercase or as a shortcut, forcing the
//! user to abandon the session. CapsLock/NumLock state was likewise never
//! reconciled.
//!
//! The fix spans three layers, each pinned here (axum-test cannot drive a
//! live WebSocket and `rdp_proxy` is `None` in tests, so the WS loop
//! behavior is covered by unit tests in `handlers/websocket.rs` and by
//! the proxy's own invariant tests):
//!
//! 1. Frontend: `release_keys` sent on canvas blur / tab switch / WS
//!    (re)open; lock-key states attached to every keydown.
//! 2. Web WS contract: `RdpCommand::ReleaseKeys` forwarded to the proxy
//!    as `RdpInputEvent::ReleaseAll`, WITHOUT touching the login-session
//!    activity throttle (a blur is the user leaving, not interacting).
//! 3. E2E over the real HTTP surface: the shipped viewer page carries
//!    the `@blur` binding for an authenticated session owner.

use axum::http::header;
use serial_test::serial;

use crate::common::TestApp;
use crate::fixtures::{
    create_simple_rdp_asset, create_test_session_with_uuid, create_test_user,
    grant_user_access_to_asset, unique_name,
};

const WEBSOCKET_SRC: &str = include_str!("../../src/handlers/websocket.rs");
const RDP_TEMPLATE_SRC: &str = include_str!("../../templates/sessions/rdp.html");
const COMPONENTS_JS_SRC: &str = include_str!("../../static/js/vauban-components.js");

// =============================================================================
// E2E: the shipped viewer page carries the fix
// =============================================================================

/// Full HTTP flow: an authenticated owner of an active RDP session
/// receives a viewer page whose canvas carries the `@blur` release
/// binding. This is the same navigation the production user performs.
#[tokio::test]
#[serial]
async fn rdp_viewer_page_ships_blur_release_binding() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let owner = create_test_user(&mut conn, &app.auth_service, &unique_name("relkeys_own")).await;
    let asset_id =
        create_simple_rdp_asset(&mut conn, &unique_name("relkeys_asset"), owner.user.id).await;
    grant_user_access_to_asset(
        &mut conn,
        owner.user.id,
        asset_id,
        &unique_name("relkeys_grant"),
        &["rdp"],
    )
    .await;
    let (_sid, session_uuid) =
        create_test_session_with_uuid(&mut conn, owner.user.id, asset_id, "rdp", "active").await;

    drop(conn);

    let resp = app
        .server
        .get(&format!("/sessions/rdp/{}", session_uuid))
        .add_header(header::COOKIE, format!("access_token={}", owner.token))
        .await;
    assert_eq!(
        resp.status_code().as_u16(),
        200,
        "session owner must receive the RDP viewer page"
    );

    let body = resp.text();
    assert!(
        body.contains("@blur=\"releaseKeys()\""),
        "the shipped RDP viewer canvas must release keys on blur \
         (stuck-modifier fix)"
    );
    assert!(
        body.contains("@keydown.prevent=\"onKeyDown($event)\""),
        "the keydown binding must remain in place next to the blur binding"
    );
}

// =============================================================================
// Structural pins: frontend JS
// =============================================================================

/// The RDP Alpine component must fire `releaseKeys()` on window blur AND
/// tab visibility loss, and clean both listeners up in `destroy`.
#[test]
fn frontend_releases_keys_on_focus_loss() {
    assert!(
        COMPONENTS_JS_SRC.contains("window.addEventListener('blur', this._blurHandler)"),
        "rdpViewer must register a window blur listener that releases keys"
    );
    assert!(
        COMPONENTS_JS_SRC
            .contains("document.addEventListener('visibilitychange', this._visibilityHandler)"),
        "rdpViewer must register a visibilitychange listener that releases keys"
    );
    assert!(
        COMPONENTS_JS_SRC.contains("window.removeEventListener('blur', this._blurHandler)"),
        "destroy must unregister the blur listener"
    );
    assert!(
        COMPONENTS_JS_SRC
            .contains("document.removeEventListener('visibilitychange', this._visibilityHandler)"),
        "destroy must unregister the visibilitychange listener"
    );
    assert!(
        COMPONENTS_JS_SRC.contains("type: 'release_keys'"),
        "releaseKeys() must send the release_keys command"
    );
}

/// The proxy session survives WebSocket reconnects: the frontend must
/// purge stale key state as soon as the socket (re)opens.
#[test]
fn frontend_releases_keys_on_ws_open() {
    // Scope to the rdpViewer component: other components (SSH terminal)
    // define their own ws.onopen without key state to purge.
    let rdp_idx = COMPONENTS_JS_SRC
        .find("Alpine.data('rdpViewer'")
        .expect("vauban-components.js must define the rdpViewer component");
    let rdp_src = &COMPONENTS_JS_SRC[rdp_idx..];
    let onopen_idx = rdp_src
        .find("this.ws.onopen")
        .expect("rdpViewer must define ws.onopen");
    let onmessage_idx = rdp_src
        .find("this.ws.onmessage")
        .expect("rdpViewer must define ws.onmessage");
    assert!(
        rdp_src[onopen_idx..onmessage_idx].contains("releaseKeys()"),
        "rdpViewer ws.onopen must call releaseKeys() to purge state from a \
         previous socket"
    );
}

/// Every keydown must report the browser lock-key states so the proxy
/// can emit an RDP Synchronize Event when they drift.
#[test]
fn frontend_keydown_reports_lock_states() {
    for lock in ["CapsLock", "NumLock", "ScrollLock"] {
        assert!(
            COMPONENTS_JS_SRC.contains(&format!("e.getModifierState('{lock}')")),
            "onKeyDown must report {lock} via getModifierState"
        );
    }
}

/// The viewer template must bind blur on the canvas itself (covers
/// in-page focus loss, e.g. clicking the toolbar).
#[test]
fn rdp_template_canvas_binds_blur() {
    assert!(
        RDP_TEMPLATE_SRC.contains("@blur=\"releaseKeys()\""),
        "sessions/rdp.html canvas must carry the @blur release binding"
    );
}

// =============================================================================
// Structural pins: web WS contract
// =============================================================================

/// The RDP WS loop must forward ReleaseKeys to the proxy as
/// RdpInputEvent::ReleaseAll.
#[test]
fn ws_loop_forwards_release_keys_to_proxy() {
    let arm_idx = WEBSOCKET_SRC
        .find("RdpCommand::ReleaseKeys => {")
        .expect("the RDP WS loop must carry a dedicated ReleaseKeys arm");
    let arm = &WEBSOCKET_SRC[arm_idx..];
    let arm_end = arm.find("RdpCommand::MouseMove").unwrap_or(arm.len());
    assert!(
        arm[..arm_end].contains("RdpInputEvent::ReleaseAll"),
        "the ReleaseKeys arm must forward RdpInputEvent::ReleaseAll to the proxy"
    );
}

/// ReleaseKeys fires on blur -- the user LEAVING -- so it must never
/// refresh `auth_sessions.last_activity`. Only the catch-all input arm
/// (real keyboard/mouse interaction) may touch the activity throttle.
#[test]
fn release_keys_arm_does_not_touch_activity_throttle() {
    let arm_idx = WEBSOCKET_SRC
        .find("RdpCommand::ReleaseKeys => {")
        .expect("the RDP WS loop must carry a dedicated ReleaseKeys arm");
    let arm = &WEBSOCKET_SRC[arm_idx..];
    // The arm ends where the catch-all input arm begins.
    let arm_end = arm
        .find("_ => {")
        .expect("the catch-all input arm must follow the ReleaseKeys arm");
    assert!(
        !arm[..arm_end].contains("activity_throttle"),
        "the ReleaseKeys arm must NOT touch the activity throttle: a blur \
         is the user leaving, not interacting"
    );
}

/// The Key command must plumb the three lock-key states through to the
/// proxy-bound RdpInputEvent::Keyboard.
#[test]
fn ws_key_mapping_carries_lock_states() {
    for field in ["caps_lock", "num_lock", "scroll_lock"] {
        let occurrences = WEBSOCKET_SRC.matches(field).count();
        assert!(
            occurrences >= 2,
            "`{field}` must appear in both RdpCommand::Key and the \
             RdpInputEvent::Keyboard mapping; found {occurrences} occurrence(s)"
        );
    }
}

/// The release-keys additions must not disturb the canonical WS
/// lifecycle log literals (websocket-logging convention).
#[test]
fn ws_lifecycle_logs_preserved_after_release_keys() {
    for literal in [
        "WebSocket connection requested",
        "WebSocket connected",
        "WebSocket closed",
        "WebSocket disconnected",
    ] {
        assert!(
            WEBSOCKET_SRC.contains(literal),
            "lifecycle log literal `{literal}` must remain present"
        );
    }
}
