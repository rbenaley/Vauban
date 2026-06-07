//! Tests for the generalized login-expiry redirect.
//!
//! The always-present `/ws/notifications` channel is the single global
//! liveness signal: a periodic re-validation arm pushes the canonical
//! force-logout OOB fragment so every htmx-ws view (dashboard, lists,
//! detail) bounces to `/login` without waiting for a click.
//!
//! Layered, no live-socket harness (axum-test cannot drive a real WS, cf.
//! `tests/ws/endpoints_test.rs`):
//! 1. unit of the single-source fragment helper;
//! 2. structural pins (single-source factoring + notifications arm wiring);
//! 3. the real delivery seam (UserConnectionRegistry register -> push ->
//!    receiver), which IS end-to-end testable;
//! 4. login-page reason banner pin.

use tokio::sync::mpsc::error::TryRecvError;

use vauban_web::services::connections::UserConnectionRegistry;
use vauban_web::services::session_activity::force_logout_oob;

const WEBSOCKET_SRC: &str = include_str!("../../src/handlers/websocket.rs");
const USERS_SRC: &str = include_str!("../../src/handlers/web/users.rs");
const LOGIN_HTML: &str = include_str!("../../templates/accounts/login.html");

// ─── Unit: the single-source fragment ────────────────────────────────────────

/// The fragment targets `#force-logout`, is an OOB swap, and triggers a
/// real navigation to `/login?reason=<reason>` for each canonical reason.
#[test]
fn force_logout_oob_contains_canonical_redirect_for_each_reason() {
    for reason in ["session_revoked", "account_deactivated", "session_expired"] {
        let html = force_logout_oob(reason);
        assert!(
            html.contains(r#"id="force-logout""#),
            "fragment must target #force-logout: {html}"
        );
        assert!(
            html.contains(r#"hx-swap-oob="innerHTML""#),
            "fragment must be an OOB swap: {html}"
        );
        assert!(
            html.contains(&format!(
                "window.location.replace('/login?reason={reason}')"
            )),
            "fragment must navigate to /login?reason={reason}: {html}"
        );
    }
}

// ─── Structural: single-source factoring ─────────────────────────────────────

/// The raw force-logout fragment literal must live ONLY in the helper
/// (`session_activity::force_logout_oob`). Neither `users.rs` nor
/// `websocket.rs` may re-inline it; both must go through the helper. This
/// pins the single-source-of-truth invariant.
#[test]
fn force_logout_fragment_is_single_sourced() {
    for (label, src) in [("users.rs", USERS_SRC), ("websocket.rs", WEBSOCKET_SRC)] {
        assert!(
            !src.contains(r#"id="force-logout" hx-swap-oob"#),
            "{label} must NOT inline the force-logout fragment; call \
             session_activity::force_logout_oob() instead"
        );
        assert!(
            src.contains("force_logout_oob("),
            "{label} must produce the force-logout fragment via the shared helper"
        );
    }
    // The helper's two admin call sites must remain (deactivate + revoke).
    assert!(
        USERS_SRC.matches("force_logout_oob(").count() >= 2,
        "users.rs must keep both admin force-logout call sites via the helper"
    );
}

// ─── Structural: notifications re-validation arm ─────────────────────────────

/// Slice `handle_notifications_socket` so assertions target that handler.
fn notifications_handler_src() -> &'static str {
    let start = WEBSOCKET_SRC
        .find("async fn handle_notifications_socket")
        .expect("handle_notifications_socket must exist");
    let rest = &WEBSOCKET_SRC[start + 1..];
    let end = rest
        .find("\nasync fn ")
        .map(|e| start + 1 + e)
        .unwrap_or(WEBSOCKET_SRC.len());
    &WEBSOCKET_SRC[start..end]
}

/// The notifications handler must wire the periodic liveness re-validation
/// and, on expiry, push the canonical fragment + record the auth_expired
/// cause.
#[test]
fn notifications_handler_wires_revalidation_arm() {
    let src = notifications_handler_src();
    assert!(
        src.contains("REVALIDATE_INTERVAL_SECS"),
        "notifications handler must re-use REVALIDATE_INTERVAL_SECS"
    );
    assert!(
        src.contains("is_login_session_live(&state, auth_session.0)"),
        "notifications handler must re-validate via is_login_session_live"
    );
    assert!(
        src.contains(r#"force_logout_oob("session_expired")"#),
        "notifications handler must push the session_expired force-logout fragment"
    );
    assert!(
        src.contains(r#"close_cause = "auth_expired""#),
        "notifications handler must record the auth_expired close cause"
    );
}

/// The notifications additions must not disturb the canonical lifecycle
/// log literals.
#[test]
fn notifications_handler_preserves_lifecycle_logs() {
    let src = notifications_handler_src();
    for literal in ["WebSocket connected", "WebSocket closed", "WebSocket disconnected"] {
        assert!(
            src.contains(literal),
            "lifecycle log literal `{literal}` must remain in the notifications handler"
        );
    }
}

// ─── E2E delivery seam (UserConnectionRegistry) ──────────────────────────────

/// Registering a browser connection then broadcasting the force-logout
/// fragment to that user delivers the canonical redirect to the
/// connection's receiver. Exercises the real transport end-to-end (the
/// only WS seam the harness can drive).
#[tokio::test]
async fn force_logout_is_delivered_to_registered_connection() {
    let registry = UserConnectionRegistry::default();
    let user_uuid = "11111111-1111-1111-1111-111111111111";
    let (_conn_id, mut rx) = registry.register(user_uuid, "token-hash-a".to_string()).await;

    registry
        .send_personalized(user_uuid, |_token_hash| {
            force_logout_oob("session_expired")
        })
        .await;

    let received = rx.recv().await.expect("connection must receive the fragment");
    assert_eq!(received, force_logout_oob("session_expired"));
    assert!(received.contains("window.location.replace('/login?reason=session_expired')"));
}

/// The targeted (token_hash) variant used by admin revoke delivers only to
/// the matching browser; non-matching connections receive nothing.
#[tokio::test]
async fn force_logout_to_matching_targets_only_the_revoked_browser() {
    let registry = UserConnectionRegistry::default();
    let user_uuid = "22222222-2222-2222-2222-222222222222";
    let (_id_a, mut rx_match) = registry.register(user_uuid, "hash-match".to_string()).await;
    let (_id_b, mut rx_other) = registry.register(user_uuid, "hash-other".to_string()).await;

    let fragment = force_logout_oob("session_revoked");
    registry
        .send_to_matching(user_uuid, "hash-match", &fragment)
        .await;

    assert_eq!(
        rx_match.recv().await.expect("matching browser receives redirect"),
        fragment
    );
    assert_eq!(
        rx_other.try_recv().expect_err("non-matching browser must receive nothing"),
        TryRecvError::Empty
    );
}

// ─── Login-page reason banner ────────────────────────────────────────────────

/// The login page must render a banner for each redirect reason in the
/// taxonomy, including the new `session_expired`.
#[test]
fn login_page_renders_banner_for_every_reason() {
    for reason in ["session_revoked", "account_deactivated", "session_expired"] {
        assert!(
            LOGIN_HTML.contains(&format!("reason === '{reason}'")),
            "login.html must render a banner for reason `{reason}`"
        );
    }
}
