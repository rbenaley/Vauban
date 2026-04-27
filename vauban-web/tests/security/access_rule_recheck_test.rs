//! VAUBAN Web - Access-rule fail-fast re-check tests.
//!
//! Cement the post-audit guarantee that EVERY consumption of an
//! existing `proxy_sessions` row triggers a fresh evaluation of the
//! matching access rule via the vauban-access `VerifySessionAccess`
//! RPC. Concretely: if the access rule that originally authorised a
//! session is later deactivated, expires, becomes not-yet-valid, or
//! its protocol set no longer covers the session's protocol, the next
//! page-load (HTML viewer) AND the next WebSocket handshake MUST be
//! rejected (collapsed to 404 to keep the anti-enumeration
//! discipline).
//!
//! Out of scope here: in-flight session interruption. Once a WS link
//! is up, no recheck is performed before the next handshake. That
//! trade-off is documented in the IAM architecture doc.

use axum::http::header;
use serial_test::serial;

use crate::common::TestApp;
use crate::fixtures::{
    create_simple_rdp_asset, create_simple_ssh_asset, create_test_session_with_uuid,
    create_test_user, deactivate_access_rule, grant_user_access_to_asset, set_access_rule_validity,
    unique_name,
};

async fn terminal_page_get(
    app: &TestApp,
    session_uuid: &str,
    token: &str,
) -> axum_test::TestResponse {
    app.server
        .get(&format!("/sessions/terminal/{}", session_uuid))
        .add_header(header::COOKIE, format!("access_token={}", token))
        .await
}

async fn rdp_page_get(app: &TestApp, session_uuid: &str, token: &str) -> axum_test::TestResponse {
    app.server
        .get(&format!("/sessions/rdp/{}", session_uuid))
        .add_header(header::COOKIE, format!("access_token={}", token))
        .await
}

/// WebSocket terminal handshake (`/ws/terminal/{session_id}`). The
/// handler returns 4xx without WS upgrade headers, but the
/// `ws_session_guard` middleware is what we actually exercise: its
/// pre-handshake authorization decision must reject revoked rules.
async fn ws_terminal_get(
    app: &TestApp,
    session_uuid: &str,
    token: &str,
) -> axum_test::TestResponse {
    app.server
        .get(&format!("/ws/terminal/{}", session_uuid))
        .add_header(header::AUTHORIZATION, app.auth_header(token))
        .await
}

// =============================================================================
// SSH HTML viewer (terminal_page) -- 4 rejection paths
// =============================================================================

/// SECURITY: a rule that was active at session creation but is later
/// deactivated must immediately stop further HTML page-loads. Today
/// (pre-fix) `terminal_page` only re-checks ownership and renders a
/// full 200 even after the rule is revoked.
#[tokio::test]
#[serial]
async fn test_revoked_access_rule_blocks_terminal_page_reload() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("rev_term")).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("rev_term_asset"), user.user.id).await;
    let (rule_uuid, _ag) = grant_user_access_to_asset(
        &mut conn,
        user.user.id,
        asset_id,
        &unique_name("rev_term_grant"),
        &["ssh"],
    )
    .await;
    let (_sid, session_uuid) =
        create_test_session_with_uuid(&mut conn, user.user.id, asset_id, "ssh", "active").await;

    // First page load succeeds (rule is active).
    drop(conn);
    let ok = terminal_page_get(app, &session_uuid.to_string(), &user.token).await;
    assert_eq!(
        ok.status_code().as_u16(),
        200,
        "owner with an active rule must initially get the terminal HTML"
    );

    // Revoke the rule, then the next reload must collapse to 404.
    let mut conn = app.get_conn().await;
    deactivate_access_rule(&mut conn, rule_uuid).await;
    drop(conn);
    let denied = terminal_page_get(app, &session_uuid.to_string(), &user.token).await;
    assert_eq!(
        denied.status_code().as_u16(),
        404,
        "after rule revocation the page must collapse to 404 (fail-fast \
         access-rule recheck)"
    );
}

#[tokio::test]
#[serial]
async fn test_expired_access_rule_blocks_terminal_page() {
    use chrono::{Duration, Utc};
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("exp_term")).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("exp_term_asset"), user.user.id).await;
    let (rule_uuid, _ag) = grant_user_access_to_asset(
        &mut conn,
        user.user.id,
        asset_id,
        &unique_name("exp_term_grant"),
        &["ssh"],
    )
    .await;
    let (_sid, session_uuid) =
        create_test_session_with_uuid(&mut conn, user.user.id, asset_id, "ssh", "active").await;
    set_access_rule_validity(
        &mut conn,
        rule_uuid,
        None,
        Some(Utc::now() - Duration::hours(1)),
    )
    .await;

    drop(conn);
    let resp = terminal_page_get(app, &session_uuid.to_string(), &user.token).await;
    assert_eq!(
        resp.status_code().as_u16(),
        404,
        "expired rule must immediately block further consumption"
    );
}

#[tokio::test]
#[serial]
async fn test_not_yet_valid_access_rule_blocks_terminal_page() {
    use chrono::{Duration, Utc};
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("nyv_term")).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("nyv_term_asset"), user.user.id).await;
    let (rule_uuid, _ag) = grant_user_access_to_asset(
        &mut conn,
        user.user.id,
        asset_id,
        &unique_name("nyv_term_grant"),
        &["ssh"],
    )
    .await;
    let (_sid, session_uuid) =
        create_test_session_with_uuid(&mut conn, user.user.id, asset_id, "ssh", "active").await;
    set_access_rule_validity(
        &mut conn,
        rule_uuid,
        Some(Utc::now() + Duration::hours(1)),
        None,
    )
    .await;

    drop(conn);
    let resp = terminal_page_get(app, &session_uuid.to_string(), &user.token).await;
    assert_eq!(
        resp.status_code().as_u16(),
        404,
        "rule with future valid_from must immediately block consumption"
    );
}

/// Protocol-mismatch: rule grants only `ssh`, but the session was
/// opened on `rdp`. The fail-fast recheck must reject the page-load.
#[tokio::test]
#[serial]
async fn test_protocol_mismatch_blocks_rdp_page() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("pm_rdp")).await;
    let asset_id =
        create_simple_rdp_asset(&mut conn, &unique_name("pm_rdp_asset"), user.user.id).await;
    let (_rule_uuid, _ag) = grant_user_access_to_asset(
        &mut conn,
        user.user.id,
        asset_id,
        &unique_name("pm_rdp_grant"),
        &["ssh"], // SSH only -- session below is RDP.
    )
    .await;
    let (_sid, session_uuid) =
        create_test_session_with_uuid(&mut conn, user.user.id, asset_id, "rdp", "active").await;

    drop(conn);
    let resp = rdp_page_get(app, &session_uuid.to_string(), &user.token).await;
    assert_eq!(
        resp.status_code().as_u16(),
        404,
        "rule covers ssh only, session is rdp -> protocol mismatch -> 404"
    );
}

// =============================================================================
// RDP HTML viewer (rdp_page) -- revocation
// =============================================================================

#[tokio::test]
#[serial]
async fn test_revoked_access_rule_blocks_rdp_page_reload() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("rev_rdp")).await;
    let asset_id =
        create_simple_rdp_asset(&mut conn, &unique_name("rev_rdp_asset"), user.user.id).await;
    let (rule_uuid, _ag) = grant_user_access_to_asset(
        &mut conn,
        user.user.id,
        asset_id,
        &unique_name("rev_rdp_grant"),
        &["rdp"],
    )
    .await;
    let (_sid, session_uuid) =
        create_test_session_with_uuid(&mut conn, user.user.id, asset_id, "rdp", "active").await;

    drop(conn);
    let ok = rdp_page_get(app, &session_uuid.to_string(), &user.token).await;
    assert_eq!(
        ok.status_code().as_u16(),
        200,
        "owner must initially get the RDP HTML wrapper"
    );

    let mut conn = app.get_conn().await;
    deactivate_access_rule(&mut conn, rule_uuid).await;
    drop(conn);
    let denied = rdp_page_get(app, &session_uuid.to_string(), &user.token).await;
    assert_eq!(
        denied.status_code().as_u16(),
        404,
        "after rule revocation the RDP page must collapse to 404"
    );
}

// =============================================================================
// WebSocket handshake (terminal_ws) -- revocation
// =============================================================================

/// SECURITY: the WebSocket handshake guard must call the same
/// instance-level decision as the HTML viewer, so the next handshake
/// after a rule revocation is rejected. Today (pre-fix)
/// `verify_session_ownership` only checks owner + status, so a
/// revoked rule does NOT block the WS upgrade.
#[tokio::test]
#[serial]
async fn test_revoked_access_rule_blocks_ws_terminal_handshake() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("rev_ws")).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("rev_ws_asset"), user.user.id).await;
    let (rule_uuid, _ag) = grant_user_access_to_asset(
        &mut conn,
        user.user.id,
        asset_id,
        &unique_name("rev_ws_grant"),
        &["ssh"],
    )
    .await;
    let (_sid, session_uuid) =
        create_test_session_with_uuid(&mut conn, user.user.id, asset_id, "ssh", "active").await;

    drop(conn);
    // Sanity: pre-revocation, the guard lets the request through to
    // the WS handler, which surfaces 4xx because the request has no
    // WS upgrade headers (anything OTHER than 403/404 means the guard
    // accepted).
    let pre = ws_terminal_get(app, &session_uuid.to_string(), &user.token).await;
    let pre_status = pre.status_code().as_u16();
    assert!(
        pre_status != 403 && pre_status != 404,
        "owner with active rule must pass the WS guard, got {}",
        pre_status
    );

    let mut conn = app.get_conn().await;
    deactivate_access_rule(&mut conn, rule_uuid).await;
    drop(conn);
    let denied = ws_terminal_get(app, &session_uuid.to_string(), &user.token).await;
    assert_eq!(
        denied.status_code().as_u16(),
        404,
        "after revocation the WS guard must reject the handshake (404 \
         anti-enum). Without the fix, the guard returns the same \
         non-403/404 status as before because access-rule is never \
         re-checked."
    );
}
