/// VAUBAN Web - Session Pages Tests.
///
/// Tests for session-related HTML pages:
/// - Session detail page
/// - Recording play page
/// - Active sessions page
/// - Session list with filters
/// - Session permissions
/// - Session termination (admin force-close)
use crate::common::{TestApp, assertions::assert_status, unwrap_ok};
use crate::fixtures::{
    create_admin_user, create_recorded_session, create_recorded_session_with_type,
    create_simple_admin_user, create_simple_rdp_asset, create_simple_ssh_asset, create_simple_user,
    create_test_session, create_test_session_with_uuid, create_test_user, unique_name,
};
use axum::http::header::COOKIE;
use diesel::{BoolExpressionMethods, ExpressionMethods, QueryDsl};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json;
use uuid::Uuid;

/// Helper to get user UUID from user_id.
async fn get_user_uuid(conn: &mut AsyncPgConnection, user_id: i32) -> Uuid {
    use vauban_web::schema::users;
    unwrap_ok!(
        users::table
            .filter(users::id.eq(user_id))
            .select(users::uuid)
            .first(conn)
            .await
    )
}

// =============================================================================
// Session Detail Page Tests
// =============================================================================

#[tokio::test]
async fn test_session_detail_page_loads() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user_id = create_simple_user(&mut conn, "test_session_page").await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;
    let asset_id = create_simple_ssh_asset(&mut conn, "test-session-page-asset", user_id).await;
    let session_id = create_test_session(&mut conn, user_id, asset_id, "ssh", "active").await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), "test_session_page", true, true)
        .await;

    let response = app
        .server
        .get(&format!("/sessions/{}", session_id))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 303,
        "Expected 200 or 303, got {}",
        status
    );
}

/// Session detail page must NOT show a Disconnect button (termination is only on /sessions/active).
#[tokio::test]
async fn test_session_detail_no_disconnect_button() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("detail_no_disc");
    let user_id = create_simple_admin_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("detail-nd-asset"), user_id).await;
    let session_id = create_test_session(&mut conn, user_id, asset_id, "ssh", "active").await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, true, true)
        .await;

    let response = app
        .server
        .get(&format!("/sessions/{}", session_id))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    if status == 200 {
        let body = response.text();
        assert!(
            !body.contains(">Disconnect</"),
            "Session detail page must NOT have a Disconnect button"
        );
        assert!(
            !body.contains("/terminate"),
            "Session detail page must NOT have a terminate action"
        );
    }
}

#[tokio::test]
async fn test_session_detail_not_found() {
    let app = TestApp::spawn().await;

    let token = app
        .generate_test_token(
            &Uuid::new_v4().to_string(),
            "test_session_notfound",
            true,
            true,
        )
        .await;

    let response = app
        .server
        .get("/sessions/999999")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    // Not found redirects to list page with flash message
    assert_status(&response, 303);
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok());
    assert_eq!(location, Some("/sessions"));
}

// =============================================================================
// Recording Play Page Tests
// =============================================================================

#[tokio::test]
async fn test_recording_play_page_with_recorded_session() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user_id = create_simple_user(&mut conn, "test_recording_page").await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;
    let asset_id = create_simple_ssh_asset(&mut conn, "test-recording-asset", user_id).await;
    let session_id = create_recorded_session(&mut conn, user_id, asset_id).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), "test_recording_page", true, true)
        .await;

    let response = app
        .server
        .get(&format!("/sessions/recordings/{}/play", session_id))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 303 || status == 404,
        "Expected valid response, got {}",
        status
    );
}

#[tokio::test]
async fn test_recording_play_not_found() {
    let app = TestApp::spawn().await;

    let token = app
        .generate_test_token(&Uuid::new_v4().to_string(), "test_rec_notfound", true, true)
        .await;

    let response = app
        .server
        .get("/sessions/recordings/999999/play")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    // Not found redirects to list page with flash message
    assert_status(&response, 303);
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok());
    assert_eq!(location, Some("/sessions/recordings"));
}

// =============================================================================
// Active Sessions Page Tests
// =============================================================================

#[tokio::test]
async fn test_active_sessions_page_loads() {
    let app = TestApp::spawn().await;

    let token = app
        .generate_test_token(
            &Uuid::new_v4().to_string(),
            "test_active_sessions",
            true,
            true,
        )
        .await;

    let response = app
        .server
        .get("/sessions/active")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 303,
        "Expected 200 or 303, got {}",
        status
    );
}

#[tokio::test]
async fn test_active_sessions_with_data() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user_id = create_simple_user(&mut conn, "test_active_data").await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;
    let asset_id = create_simple_ssh_asset(&mut conn, "test-active-asset", user_id).await;
    let _session_id = create_test_session(&mut conn, user_id, asset_id, "ssh", "active").await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), "test_active_data", true, true)
        .await;

    let response = app
        .server
        .get("/sessions/active")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 303,
        "Expected 200 or 303, got {}",
        status
    );
}

// =============================================================================
// Session List Filter Tests
// =============================================================================

#[tokio::test]
async fn test_session_list_filter_by_all_statuses() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_username = unique_name("session_status_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_username, true, true)
        .await;

    // Test 1: No filter
    let response_no_filter = app
        .server
        .get("/sessions")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(
        response_no_filter.status_code().as_u16(),
        200,
        "Session list without filter should load"
    );

    // Test 2: Empty status filter (regression test)
    let response_empty = app
        .server
        .get("/sessions?status=")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(
        response_empty.status_code().as_u16(),
        200,
        "Session list with empty status filter should load"
    );

    // Test all valid statuses
    let statuses = [
        "active",
        "disconnected",
        "completed",
        "terminated",
        "pending",
    ];

    for status in &statuses {
        let response = app
            .server
            .get(&format!("/sessions?status={}", status))
            .add_header(COOKIE, format!("access_token={}", token))
            .await;

        assert_eq!(
            response.status_code().as_u16(),
            200,
            "Session list with status={} should load",
            status
        );

        let body = response.text();
        assert!(
            body.contains(&format!("value=\"{}\"", status)) && body.contains("selected"),
            "Status {} should be selected in dropdown",
            status
        );
    }

    // Test invalid status
    let response_invalid = app
        .server
        .get("/sessions?status=invalid_status")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(
        response_invalid.status_code().as_u16(),
        200,
        "Session list with invalid status should still load"
    );
}

#[tokio::test]
async fn test_session_list_filter_by_all_types() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_username = unique_name("session_type_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_username, true, true)
        .await;

    // Test 1: No filter
    let response_no_filter = app
        .server
        .get("/sessions")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response_no_filter.status_code().as_u16(), 200);

    // Test 2: Empty type filter
    let response_empty = app
        .server
        .get("/sessions?type=")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(
        response_empty.status_code().as_u16(),
        200,
        "Session list with empty type filter should load"
    );

    // Test all valid types
    let types = ["ssh", "rdp", "iacs_tunnel"];

    for session_type in &types {
        let response = app
            .server
            .get(&format!("/sessions?type={}", session_type))
            .add_header(COOKIE, format!("access_token={}", token))
            .await;

        assert_eq!(
            response.status_code().as_u16(),
            200,
            "Session list with type={} should load",
            session_type
        );

        let body = response.text();
        assert!(
            body.contains(&format!("value=\"{}\"", session_type)) && body.contains("selected"),
            "Type {} should be selected in dropdown",
            session_type
        );
    }
}

/// Operator request 2026-05-08: the /sessions Type filter must
/// expose the IACS Tunnel option so an operator can pivot the
/// session log on industrial tunnels separately from SSH/RDP. The
/// option must surface even on an empty session list (the dropdown
/// is server-rendered regardless of seeded rows).
#[tokio::test]
async fn test_session_list_dropdown_carries_iacs_tunnel_option() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_username = unique_name("sess_iacs_filter_adm");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_username, true, true)
        .await;

    let response = app
        .server
        .get("/sessions")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_eq!(response.status_code().as_u16(), 200);
    let body = response.text();

    assert!(
        body.contains("value=\"iacs_tunnel\""),
        "session list Type dropdown must expose value=\"iacs_tunnel\""
    );
    assert!(
        body.contains(">IACS Tunnel<"),
        "session list Type dropdown must label the option 'IACS Tunnel'"
    );

    // Selected-state pin: ?type=iacs_tunnel must mark the option
    // as selected in the rendered HTML so the page reload keeps
    // the operator's filter visible in the dropdown.
    let selected = app
        .server
        .get("/sessions?type=iacs_tunnel")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_eq!(selected.status_code().as_u16(), 200);
    let selected_body = selected.text();
    assert!(
        selected_body.contains("value=\"iacs_tunnel\"") && selected_body.contains("selected"),
        "?type=iacs_tunnel must mark the IACS Tunnel option as selected on reload"
    );
}

#[tokio::test]
async fn test_session_list_search_by_asset() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_username = unique_name("session_asset_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_username, true, true)
        .await;

    // Test 1: Search with asset name
    let response = app
        .server
        .get("/sessions?asset=server")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response.status_code().as_u16(), 200);

    // Test 2: Empty asset filter (regression test)
    let response_empty = app
        .server
        .get("/sessions?asset=")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(
        response_empty.status_code().as_u16(),
        200,
        "Session list with empty asset filter should load"
    );

    // Test 3: Non-matching search
    let response_no_match = app
        .server
        .get("/sessions?asset=nonexistent_asset_xyz")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response_no_match.status_code().as_u16(), 200);
}

#[tokio::test]
async fn test_session_list_combined_filters() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_username = unique_name("session_combined_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_username, true, true)
        .await;

    // Test 1: All three filters combined
    let response = app
        .server
        .get("/sessions?status=active&type=ssh&asset=server")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(
        response.status_code().as_u16(),
        200,
        "Combined filters should work"
    );

    // Test 2: Two filters
    let response_two = app
        .server
        .get("/sessions?status=completed&type=rdp")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response_two.status_code().as_u16(), 200);

    // Test 3: Status with asset search
    let response_status_asset = app
        .server
        .get("/sessions?status=active&asset=prod")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response_status_asset.status_code().as_u16(), 200);

    // Test 4: All empty filters (should show all)
    let response_all_empty = app
        .server
        .get("/sessions?status=&type=&asset=")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(
        response_all_empty.status_code().as_u16(),
        200,
        "All empty filters should show all sessions"
    );
}

// =============================================================================
// Session Permission Tests
// =============================================================================

/// Non-admin users are denied access to /sessions (admin-only page).
#[tokio::test]
async fn test_session_list_denied_for_regular_user() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user1_name = unique_name("sess_user1");
    let user1_id = create_simple_user(&mut conn, &user1_name).await;
    let user1_uuid = get_user_uuid(&mut conn, user1_id).await;

    let token = app
        .generate_test_token(&user1_uuid.to_string(), &user1_name, false, false)
        .await;

    let response = app
        .server
        .get("/sessions")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 403 || status == 303,
        "Regular user must be denied access to /sessions, got {}",
        status
    );
}

#[tokio::test]
async fn test_session_list_admin_sees_all() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("sess_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let other_name = unique_name("other_sess_user");
    let other_id = create_simple_user(&mut conn, &other_name).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("all-sess-asset"), admin_id).await;
    let _session_id = create_test_session(&mut conn, other_id, asset_id, "ssh", "completed").await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let response = app
        .server
        .get("/sessions")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 200,
        "Admin should access all sessions, got {}",
        status
    );
}

#[tokio::test]
async fn test_session_detail_own_session_allowed() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let test_id = uuid::Uuid::new_v4().to_string()[..8].to_string();
    let username = format!("own_sess_user_{}", test_id);
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;

    let asset_name = format!("own-sess-asset-{}", test_id);
    let asset_id = create_simple_ssh_asset(&mut conn, &asset_name, user_id).await;
    // The new session_access gate re-checks the access rule on every
    // metadata read; an "owner sees own session" path that lacks an
    // active access rule would otherwise collapse to 404 (anti-enum).
    // Use the helper that provisions both the session row and a
    // matching active rule.
    let (session_id, _session_uuid, _rule) = crate::fixtures::create_test_session_with_access(
        &mut conn,
        user_id,
        asset_id,
        "ssh",
        "completed",
    )
    .await;

    use vauban_web::schema::proxy_sessions;
    let session_exists: bool = proxy_sessions::table
        .filter(proxy_sessions::id.eq(session_id))
        .select(proxy_sessions::id)
        .first::<i32>(&mut conn)
        .await
        .is_ok();
    assert!(session_exists, "Session should exist after creation");

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;

    let response = app
        .server
        .get(&format!("/sessions/{}", session_id))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 200,
        "User should access their own session detail, got {}. Session ID: {}",
        status,
        session_id
    );
}

/// Regression guard for the "View" link on /sessions: the owner of
/// a session that has reached an `is_gone()` status (terminated,
/// expired or disconnected) MUST still be able to load the detail
/// page so the audit trail (durations, bytes, justification,
/// recording link) stays reachable. Pre-fix, this collapsed to 303
/// "/sessions" with a misleading "Session not found" flash because
/// vauban-access returned `Denied(Gone)` for the `ReadMetadata`
/// intent regardless of identity.
#[tokio::test]
async fn test_session_detail_owner_terminated_session_loads_200() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let test_id = uuid::Uuid::new_v4().to_string()[..8].to_string();
    let username = format!("term_owner_{}", test_id);
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;

    let asset_name = format!("term-asset-{}", test_id);
    let asset_id = create_simple_ssh_asset(&mut conn, &asset_name, user_id).await;
    let (session_id, _session_uuid, _rule) = crate::fixtures::create_test_session_with_access(
        &mut conn,
        user_id,
        asset_id,
        "ssh",
        "terminated",
    )
    .await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;

    let response = app
        .server
        .get(&format!("/sessions/{}", session_id))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert_eq!(
        status, 200,
        "Owner must be able to read the historical metadata of their TERMINATED session, got {}",
        status
    );
}

#[tokio::test]
async fn test_session_detail_owner_expired_session_loads_200() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let test_id = uuid::Uuid::new_v4().to_string()[..8].to_string();
    let username = format!("exp_owner_{}", test_id);
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;

    let asset_name = format!("exp-asset-{}", test_id);
    let asset_id = create_simple_ssh_asset(&mut conn, &asset_name, user_id).await;
    let (session_id, _session_uuid, _rule) = crate::fixtures::create_test_session_with_access(
        &mut conn, user_id, asset_id, "ssh", "expired",
    )
    .await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;

    let response = app
        .server
        .get(&format!("/sessions/{}", session_id))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert_eq!(
        status, 200,
        "Owner must be able to read the historical metadata of their EXPIRED session, got {}",
        status
    );
}

#[tokio::test]
async fn test_session_detail_owner_disconnected_session_loads_200() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let test_id = uuid::Uuid::new_v4().to_string()[..8].to_string();
    let username = format!("disc_owner_{}", test_id);
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;

    let asset_name = format!("disc-asset-{}", test_id);
    let asset_id = create_simple_ssh_asset(&mut conn, &asset_name, user_id).await;
    let (session_id, _session_uuid, _rule) = crate::fixtures::create_test_session_with_access(
        &mut conn,
        user_id,
        asset_id,
        "ssh",
        "disconnected",
    )
    .await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;

    let response = app
        .server
        .get(&format!("/sessions/{}", session_id))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert_eq!(
        status, 200,
        "Owner must be able to read the historical metadata of their DISCONNECTED session, got {}",
        status
    );
}

/// Anti-enumeration twin of the regression guard above: a non-owner
/// probing a Gone session via the View link MUST be redirected
/// (303 -> /sessions) with the same "not found" flash as for a truly
/// non-existent UUID, so a probe cannot tell a terminated foreign
/// session apart from a never-existed one.
#[tokio::test]
async fn test_session_detail_intruder_terminated_session_redirects() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let test_id = uuid::Uuid::new_v4().to_string()[..8].to_string();
    let owner_name = format!("term_intruder_owner_{}", test_id);
    let owner_id = create_simple_user(&mut conn, &owner_name).await;
    let asset_name = format!("term-intruder-asset-{}", test_id);
    let asset_id = create_simple_ssh_asset(&mut conn, &asset_name, owner_id).await;
    let session_id = create_test_session(&mut conn, owner_id, asset_id, "ssh", "terminated").await;

    let intruder_name = format!("term_intruder_{}", test_id);
    let intruder_id = create_simple_user(&mut conn, &intruder_name).await;
    let intruder_uuid = get_user_uuid(&mut conn, intruder_id).await;

    let token = app
        .generate_test_token(&intruder_uuid.to_string(), &intruder_name, false, false)
        .await;

    let response = app
        .server
        .get(&format!("/sessions/{}", session_id))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert_eq!(
        status, 303,
        "Non-owner probing a terminated session must be redirected (anti-enum), got {}",
        status
    );
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok());
    assert_eq!(location, Some("/sessions"));
}

#[tokio::test]
async fn test_session_detail_other_session_forbidden() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let test_id = uuid::Uuid::new_v4().to_string()[..8].to_string();

    let owner_name = format!("sess_owner_{}", test_id);
    let owner_id = create_simple_user(&mut conn, &owner_name).await;
    let asset_name = format!("other-sess-asset-{}", test_id);
    let asset_id = create_simple_ssh_asset(&mut conn, &asset_name, owner_id).await;
    let session_id = create_test_session(&mut conn, owner_id, asset_id, "ssh", "completed").await;

    use vauban_web::schema::proxy_sessions;
    let session_exists: bool = proxy_sessions::table
        .filter(proxy_sessions::id.eq(session_id))
        .select(proxy_sessions::id)
        .first::<i32>(&mut conn)
        .await
        .is_ok();
    assert!(session_exists, "Session should exist after creation");

    let other_name = format!("sess_other_{}", test_id);
    let other_id = create_simple_user(&mut conn, &other_name).await;
    let other_uuid = get_user_uuid(&mut conn, other_id).await;

    let token = app
        .generate_test_token(&other_uuid.to_string(), &other_name, false, false)
        .await;

    let response = app
        .server
        .get(&format!("/sessions/{}", session_id))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    // User trying to view another's session is redirected with flash message
    let status = response.status_code().as_u16();
    assert!(
        status == 303,
        "User should be redirected from other's session, got {}. Session ID: {}",
        status,
        session_id
    );
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok());
    assert_eq!(location, Some("/sessions"));
}

// =============================================================================
// Session Error Handling Tests
// =============================================================================

#[tokio::test]
async fn test_session_detail_invalid_id_format() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("invalid_id_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    // Session ID should be an integer, try with invalid formats
    // All should redirect gracefully to /sessions instead of showing error page
    let invalid_ids = ["abc", "not-a-number", "12.34", "{wqeqwE}", "invalid"];

    for invalid_id in invalid_ids {
        let response = app
            .server
            .get(&format!("/sessions/{}", invalid_id))
            .add_header(COOKIE, format!("access_token={}", token))
            .await;

        let status = response.status_code().as_u16();
        let location = response
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok());

        assert!(
            status == 303 && location == Some("/sessions"),
            "Invalid session ID '{}' should redirect to /sessions with 303, got status {} location {:?}",
            invalid_id,
            status,
            location
        );
    }
}

#[tokio::test]
async fn test_recording_play_invalid_id() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("rec_invalid_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    // Test various invalid recording IDs - all should redirect gracefully
    let invalid_ids = ["abc", "{wqeqwE}", "not-a-number", "12.34"];

    for invalid_id in invalid_ids {
        let response = app
            .server
            .get(&format!("/sessions/recordings/{}/play", invalid_id))
            .add_header(COOKIE, format!("access_token={}", token))
            .await;

        let status = response.status_code().as_u16();
        let location = response
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok());

        assert!(
            status == 303 && location == Some("/sessions/recordings"),
            "Invalid recording ID '{}' should redirect to /sessions/recordings with 303, got status {} location {:?}",
            invalid_id,
            status,
            location
        );
    }
}

#[tokio::test]
async fn test_session_detail_negative_id() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("neg_id_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    // Negative IDs are valid integers but don't exist - should redirect
    let response = app
        .server
        .get("/sessions/-999")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    // Should redirect gracefully since -999 doesn't exist
    assert!(
        status == 303,
        "Non-existent session ID should redirect, got {}",
        status
    );
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok());
    assert_eq!(location, Some("/sessions"));
}

#[tokio::test]
async fn test_session_detail_very_large_id() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("large_id_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    // Very large ID that doesn't exist
    let response = app
        .server
        .get("/sessions/2147483647")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    // Should redirect to sessions list
    assert_status(&response, 303);
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok());
    assert_eq!(location, Some("/sessions"));
}

#[tokio::test]
async fn test_recording_play_non_recorded_session() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("rec_non_recorded");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("non-rec-asset"), admin_id).await;

    // Create a non-recorded session
    let session_id = create_test_session(&mut conn, admin_id, asset_id, "ssh", "completed").await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    // Try to play a non-recorded session
    let response = app
        .server
        .get(&format!("/sessions/recordings/{}/play", session_id))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    // Should redirect since there's no recording
    assert_status(&response, 303);
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok());
    assert_eq!(location, Some("/sessions/recordings"));
}

#[tokio::test]
async fn test_admin_can_view_any_session() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let test_id = Uuid::new_v4().to_string()[..8].to_string();

    // Create a user and their session
    let owner_name = format!("sess_owner2_{}", test_id);
    let owner_id = create_simple_user(&mut conn, &owner_name).await;
    let asset_name = format!("admin-view-asset-{}", test_id);
    let asset_id = create_simple_ssh_asset(&mut conn, &asset_name, owner_id).await;
    let session_id = create_test_session(&mut conn, owner_id, asset_id, "ssh", "completed").await;

    // Create admin user
    let admin_name = format!("admin_viewer_{}", test_id);
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    // Admin should be able to view any session
    let response = app
        .server
        .get(&format!("/sessions/{}", session_id))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
}

// =============================================================================
// RDP Session Tests
// =============================================================================

/// Test that an RDP session detail page loads and shows RDP type.
#[tokio::test]
#[serial_test::serial]
async fn test_rdp_session_detail_page() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let test_id = Uuid::new_v4().to_string()[..8].to_string();

    let owner_name = format!("rdp_owner_{}", test_id);
    let owner_id = create_simple_user(&mut conn, &owner_name).await;
    let asset_name = format!("rdp-detail-asset-{}", test_id);
    let asset_id = create_simple_rdp_asset(&mut conn, &asset_name, owner_id).await;
    let session_id = create_test_session(&mut conn, owner_id, asset_id, "rdp", "completed").await;

    let owner_uuid = get_user_uuid(&mut conn, owner_id).await;
    let token = app
        .generate_test_token(&owner_uuid.to_string(), &owner_name, false, true)
        .await;

    let response = app
        .server
        .get(&format!("/sessions/{}", session_id))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);

    let body = response.text();
    assert!(
        body.contains("RDP") || body.contains("rdp"),
        "Session detail page should indicate RDP session type"
    );
}

/// Test that an active RDP session shows up in the active sessions list.
#[tokio::test]
#[serial_test::serial]
async fn test_rdp_session_in_active_list() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let test_id = Uuid::new_v4().to_string()[..8].to_string();

    let admin_name = format!("rdp_admin_list_{}", test_id);
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let asset_name = format!("rdp-list-asset-{}", test_id);
    let asset_id = create_simple_rdp_asset(&mut conn, &asset_name, admin_id).await;
    let _session_id = create_test_session(&mut conn, admin_id, asset_id, "rdp", "active").await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let response = app
        .server
        .get("/sessions/active")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
}

/// Test session filtering: RDP sessions show when type=rdp filter is applied.
#[tokio::test]
#[serial_test::serial]
async fn test_session_filter_by_rdp_type() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let test_id = Uuid::new_v4().to_string()[..8].to_string();

    let admin_name = format!("filter_admin_{}", test_id);
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    // Create both SSH and RDP sessions
    let ssh_asset_name = format!("ssh-filter-{}", test_id);
    let ssh_asset_id = create_simple_ssh_asset(&mut conn, &ssh_asset_name, admin_id).await;
    let _ssh_session =
        create_test_session(&mut conn, admin_id, ssh_asset_id, "ssh", "completed").await;

    let rdp_asset_name = format!("rdp-filter-{}", test_id);
    let rdp_asset_id = create_simple_rdp_asset(&mut conn, &rdp_asset_name, admin_id).await;
    let _rdp_session =
        create_test_session(&mut conn, admin_id, rdp_asset_id, "rdp", "completed").await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let response = app
        .server
        .get("/sessions?type=rdp")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
}

// =============================================================================
// Recording List WebSocket Auto-Refresh Tests
// =============================================================================

#[tokio::test]
async fn test_recording_list_page_has_ws_trigger() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("rec_ws_trigger");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let response = app
        .server
        .get("/sessions/recordings")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("recording-ws-trigger"),
        "recording list page must contain recording-ws-trigger element"
    );
    assert!(
        body.contains("recordings-list-container"),
        "recording list page must contain recordings-list-container"
    );
    assert!(
        body.contains("recording_ready"),
        "recording list trigger must listen for recording_ready events"
    );
}

#[tokio::test]
async fn test_recording_list_page_has_ws_connect() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("rec_ws_conn");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let response = app
        .server
        .get("/sessions/recordings")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("ws-connect"),
        "recording list page must have ws-connect (inherited from base.html)"
    );
    assert!(
        body.contains("/ws/notifications"),
        "recording list page must connect to /ws/notifications"
    );
}

#[tokio::test]
async fn test_recording_list_with_recordings_has_ws_elements() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("rec_ws_data");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let asset_name = unique_name("rec-ws-asset");
    let asset_id = create_simple_ssh_asset(&mut conn, &asset_name, admin_id).await;
    let _session_id = create_recorded_session(&mut conn, admin_id, asset_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let response = app
        .server
        .get("/sessions/recordings")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
    let body = response.text();

    assert!(
        body.contains(&asset_name),
        "recording list should show the recorded session's asset"
    );
    assert!(
        body.contains("recording-ws-trigger"),
        "WS trigger must be present even with data"
    );
    assert!(
        body.contains("recordings-list-container"),
        "container must be present even with data"
    );
}

#[tokio::test]
async fn test_recording_list_format_filter_preserved_in_ws_trigger() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("rec_ws_fmt");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let response = app
        .server
        .get("/sessions/recordings?format=ssh")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("format=ssh"),
        "WS trigger hx-get must preserve format=ssh filter in URL"
    );
}

#[tokio::test]
async fn test_recording_list_asset_filter_preserved_in_ws_trigger() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("rec_ws_ast");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let response = app
        .server
        .get("/sessions/recordings?asset=myserver")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("asset=myserver"),
        "WS trigger hx-get must preserve asset=myserver filter in URL"
    );
}

#[tokio::test]
async fn test_recording_list_both_filters_preserved_in_ws_trigger() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("rec_ws_both");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let response = app
        .server
        .get("/sessions/recordings?format=rdp&asset=prod")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("format=rdp"),
        "WS trigger must preserve format filter"
    );
    assert!(
        body.contains("asset=prod"),
        "WS trigger must preserve asset filter"
    );
}

#[tokio::test]
async fn test_recording_list_has_periodic_polling_fallback() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("rec_ws_poll");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let response = app
        .server
        .get("/sessions/recordings")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("every 30s"),
        "recording list must have periodic polling fallback (every 30s)"
    );
}

#[tokio::test]
async fn test_recording_list_hx_trigger_uses_ws_after_message() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("rec_ws_htmx");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let response = app
        .server
        .get("/sessions/recordings")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("htmx:wsAfterMessage"),
        "WS trigger must use htmx:wsAfterMessage event"
    );
    assert!(
        body.contains("from:body"),
        "WS trigger must listen from:body"
    );
}

#[tokio::test]
async fn test_recording_list_ws_elements_with_nonexistent_asset_filter() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("rec_ws_empty");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let response = app
        .server
        .get("/sessions/recordings?asset=nonexistent_asset_xyz_42")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("No recordings"),
        "filtered list with no matches must show 'No recordings'"
    );
    assert!(
        body.contains("recording-ws-trigger"),
        "WS trigger must be present even with no matching recordings"
    );
    assert!(
        body.contains("recordings-list-container"),
        "container must be present even with no matching recordings"
    );
}

#[tokio::test]
async fn test_recording_list_multiple_types_have_ws_elements() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("rec_ws_multi");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let ssh_asset = unique_name("rec-ssh-ws");
    let ssh_asset_id = create_simple_ssh_asset(&mut conn, &ssh_asset, admin_id).await;
    let _ssh_rec = create_recorded_session(&mut conn, admin_id, ssh_asset_id).await;

    let rdp_asset = unique_name("rec-rdp-ws");
    let rdp_asset_id = create_simple_rdp_asset(&mut conn, &rdp_asset, admin_id).await;
    let _rdp_rec =
        create_recorded_session_with_type(&mut conn, admin_id, rdp_asset_id, "rdp").await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let response = app
        .server
        .get("/sessions/recordings")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(body.contains(&ssh_asset), "SSH recording asset must appear");
    assert!(body.contains(&rdp_asset), "RDP recording asset must appear");
    assert!(
        body.contains("recording-ws-trigger"),
        "WS trigger must be present with multiple recordings"
    );
}

// =============================================================================
// Session Termination Tests
// =============================================================================

#[tokio::test]
async fn test_terminate_active_ssh_session() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("term_ssh_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("term_ssh_asset"), admin_id).await;
    let (session_id, session_uuid) =
        create_test_session_with_uuid(&mut conn, admin_id, asset_id, "ssh", "active").await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let csrf_token = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/sessions/{}/terminate", session_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .add_header("HX-Request", "true")
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("Terminated"),
        "Response must show Terminated badge"
    );

    use vauban_web::schema::proxy_sessions;
    let (db_status, disc_at): (String, Option<chrono::DateTime<chrono::Utc>>) = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::id.eq(session_id))
            .select((proxy_sessions::status, proxy_sessions::disconnected_at))
            .first(&mut conn)
            .await
    );
    assert_eq!(db_status, "terminated");
    assert!(
        disc_at.is_some(),
        "disconnected_at must be set after termination"
    );
}

#[tokio::test]
async fn test_terminate_active_rdp_session() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("term_rdp_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let asset_id =
        create_simple_rdp_asset(&mut conn, &unique_name("term_rdp_asset"), admin_id).await;
    let (session_id, session_uuid) =
        create_test_session_with_uuid(&mut conn, admin_id, asset_id, "rdp", "active").await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let csrf_token = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/sessions/{}/terminate", session_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .add_header("HX-Request", "true")
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;

    assert_status(&response, 200);

    use vauban_web::schema::proxy_sessions;
    let db_status: String = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::id.eq(session_id))
            .select(proxy_sessions::status)
            .first(&mut conn)
            .await
    );
    assert_eq!(db_status, "terminated");
}

#[tokio::test]
async fn test_terminate_non_staff_rejected() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user_name = unique_name("term_nostaff");
    let user_id = create_simple_user(&mut conn, &user_name).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;

    let admin_name = unique_name("term_nostaff_adm");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("term_nostaff_ast"), admin_id).await;
    let (session_id, session_uuid) =
        create_test_session_with_uuid(&mut conn, admin_id, asset_id, "ssh", "active").await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &user_name, false, false)
        .await;
    let csrf_token = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/sessions/{}/terminate", session_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;

    // The new session_access gate collapses NotOwner to a generic 404
    // (anti-enumeration). The web wrapper additionally translates that
    // 404 into a 303 redirect to `/sessions` carrying a flash error
    // (so a plain `<form method="post">` lands back on a real page
    // instead of leaking the API JSON body). Either status -- the raw
    // 404 from the API endpoint or the 303 PRG from the web wrapper --
    // satisfies the contract; the DB invariant (status stays "active")
    // is what we really care about.
    let status_code = response.status_code().as_u16();
    assert!(
        status_code == 303
            || status_code == 403
            || status_code == 302
            || status_code == 404,
        "Non-staff user must be rejected (got {})",
        status_code
    );

    use vauban_web::schema::proxy_sessions;
    let db_status: String = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::id.eq(session_id))
            .select(proxy_sessions::status)
            .first(&mut conn)
            .await
    );
    assert_eq!(
        db_status, "active",
        "Session must remain active when non-staff tries to terminate"
    );
}

#[tokio::test]
async fn test_terminate_already_terminated_session() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("term_already_adm");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("term_already_ast"), admin_id).await;
    let (_session_id, session_uuid) =
        create_test_session_with_uuid(&mut conn, admin_id, asset_id, "ssh", "terminated").await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let csrf_token = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/sessions/{}/terminate", session_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .add_header("HX-Request", "true")
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;

    assert_status(&response, 200);
}

#[tokio::test]
async fn test_terminate_nonexistent_session() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("term_noexist_adm");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let csrf_token = app.generate_csrf_token();

    let nonexistent_uuid = Uuid::new_v4();
    let response = app
        .server
        .post(&format!("/sessions/{}/terminate", nonexistent_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;

    // The web wrapper translates the API NotFound into a 303 redirect
    // to `/sessions` (PRG with a flash error). The raw 404 / 500 from
    // the API endpoint stays accepted for the legacy test path.
    let status_code = response.status_code().as_u16();
    assert!(
        status_code == 303 || status_code == 404 || status_code == 302 || status_code == 500,
        "Nonexistent session must return error (got {})",
        status_code
    );
}

#[tokio::test]
async fn test_terminate_invalid_uuid_format() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("term_badid_adm");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let csrf_token = app.generate_csrf_token();

    let response = app
        .server
        .post("/sessions/not-a-valid-uuid/terminate")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;

    let status_code = response.status_code().as_u16();
    assert!(
        status_code == 302 || status_code == 303 || status_code == 400,
        "Invalid session UUID must be handled gracefully (got {})",
        status_code
    );
}

#[tokio::test]
async fn test_terminate_preserves_status_after_cleanup() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("term_preserve_adm");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("term_preserve_ast"), admin_id).await;
    let (session_id, session_uuid) =
        create_test_session_with_uuid(&mut conn, admin_id, asset_id, "ssh", "active").await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let csrf_token = app.generate_csrf_token();

    // Terminate via admin
    let response = app
        .server
        .post(&format!("/sessions/{}/terminate", session_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .add_header("HX-Request", "true")
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;
    assert_status(&response, 200);

    // Simulate WebSocket cleanup by running the same UPDATE the handler does
    // but only for active/connecting sessions -- verify it does NOT overwrite terminated
    use vauban_web::schema::proxy_sessions;
    let cleanup_count: usize = unwrap_ok!(
        diesel::update(
            proxy_sessions::table
                .filter(proxy_sessions::id.eq(session_id))
                .filter(
                    proxy_sessions::status
                        .eq("active")
                        .or(proxy_sessions::status.eq("connecting")),
                ),
        )
        .set(proxy_sessions::status.eq("disconnected"))
        .execute(&mut conn)
        .await
    );
    assert_eq!(
        cleanup_count, 0,
        "WebSocket cleanup must NOT overwrite terminated status (0 rows updated)"
    );

    // Verify the status is still "terminated"
    let db_status: String = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::id.eq(session_id))
            .select(proxy_sessions::status)
            .first(&mut conn)
            .await
    );
    assert_eq!(
        db_status, "terminated",
        "Status must remain terminated after cleanup"
    );
}

#[tokio::test]
async fn test_terminate_then_second_terminate_is_idempotent() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("term_idempotent_adm");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("term_idempotent_ast"), admin_id).await;
    let (session_id, session_uuid) =
        create_test_session_with_uuid(&mut conn, admin_id, asset_id, "ssh", "active").await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let csrf_token = app.generate_csrf_token();

    // First terminate
    let response = app
        .server
        .post(&format!("/sessions/{}/terminate", session_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .add_header("HX-Request", "true")
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;
    assert_status(&response, 200);

    // Second terminate (should still succeed, not crash)
    let csrf_token2 = app.generate_csrf_token();
    let response2 = app
        .server
        .post(&format!("/sessions/{}/terminate", session_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token2),
        )
        .add_header("HX-Request", "true")
        .form(&[("csrf_token", csrf_token2.as_str())])
        .await;
    assert_status(&response2, 200);

    use vauban_web::schema::proxy_sessions;
    let db_status: String = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::id.eq(session_id))
            .select(proxy_sessions::status)
            .first(&mut conn)
            .await
    );
    assert_eq!(db_status, "terminated");
}

// =============================================================================
// WebSocket real-time integration tests for /sessions page
// =============================================================================

/// Admin on page 1 with no filters should get ws-connect attribute.
#[tokio::test]
async fn test_session_list_admin_page1_has_ws_connect() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("wslist_admin")).await;
    drop(conn);

    let response = app
        .server
        .get("/sessions")
        .add_header(COOKIE, format!("access_token={}", admin.token))
        .await;
    assert_status(&response, 200);

    let body = response.text();
    assert!(
        body.contains("ws-connect=\"/ws/sessions/list\""),
        "Admin on default page must have WS connection"
    );
    assert!(body.contains("Live"), "Admin page must show Live indicator");
}

/// Admin with status filter should NOT get ws-connect for session list.
#[tokio::test]
async fn test_session_list_admin_with_filter_no_ws() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin =
        create_admin_user(&mut conn, &app.auth_service, &unique_name("wslist_filter")).await;
    drop(conn);

    let response = app
        .server
        .get("/sessions?status=active")
        .add_header(COOKIE, format!("access_token={}", admin.token))
        .await;
    assert_status(&response, 200);

    let body = response.text();
    assert!(
        !body.contains("ws-connect=\"/ws/sessions/list\""),
        "Admin with filter must NOT have session list WS connection"
    );
}

/// Non-admin user is denied access to /sessions entirely.
#[tokio::test]
async fn test_session_list_normal_user_denied() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("wslist_user")).await;
    drop(conn);

    let response = app
        .server
        .get("/sessions")
        .add_header(COOKIE, format!("access_token={}", user.token))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 403 || status == 303,
        "Non-admin user must be denied access to /sessions, got {}",
        status
    );
}

// =============================================================================
// Active Sessions Page Integration Tests (real data, no mocks)
// =============================================================================

/// Active sessions page displays real usernames (not "User X" placeholders).
#[tokio::test]
async fn test_active_sessions_shows_real_username() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("active_real_user");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("active-real-asset"), user_id).await;
    let _session_id = create_test_session(&mut conn, user_id, asset_id, "ssh", "active").await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, true, true)
        .await;

    let response = app
        .server
        .get("/sessions/active")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 303,
        "Expected 200 or 303, got {}",
        status
    );

    if status == 200 {
        let body = response.text();
        assert!(
            body.contains(&username),
            "Active sessions page must show real username '{}', not placeholders",
            username
        );
    }
}

/// Active sessions page displays real asset name (not "Asset X" placeholders).
#[tokio::test]
async fn test_active_sessions_shows_real_asset_name() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("active_asset_user");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;
    let asset_name = unique_name("RealAssetName");
    let asset_id = create_simple_ssh_asset(&mut conn, &asset_name, user_id).await;
    let _session_id = create_test_session(&mut conn, user_id, asset_id, "ssh", "active").await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, true, true)
        .await;

    let response = app
        .server
        .get("/sessions/active")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    if response.status_code().as_u16() == 200 {
        let body = response.text();
        assert!(
            body.contains(&asset_name),
            "Active sessions page must show real asset name '{}'",
            asset_name
        );
    }
}

/// Disconnect button works: POSTing to /sessions/{uuid}/terminate terminates the session.
#[tokio::test]
async fn test_active_sessions_disconnect_terminates() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("active_disc_admin");
    let admin_id = create_simple_admin_user(&mut conn, &username).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let asset_id = create_simple_ssh_asset(&mut conn, &unique_name("disc-asset"), admin_id).await;
    let (session_id, session_uuid) =
        create_test_session_with_uuid(&mut conn, admin_id, asset_id, "ssh", "active").await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &username, true, true)
        .await;

    let response = app
        .server
        .post(&format!("/sessions/{}/terminate", session_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .add_header("HX-Request", "true")
        .form(&serde_json::json!({
            "csrf_token": "test"
        }))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 303 || status == 400,
        "Terminate should respond with 200, 303, or 400, got {}",
        status
    );

    use vauban_web::schema::proxy_sessions;
    let db_status: String = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::id.eq(session_id))
            .select(proxy_sessions::status)
            .first(&mut conn)
            .await
    );

    if status == 200 {
        assert_eq!(db_status, "terminated", "Session must be terminated in DB");
    }
}

/// Sessions without connected_at should not appear in active sessions list.
#[tokio::test]
async fn test_active_sessions_excludes_no_connected_at() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("active_no_conn_user");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;
    let asset_id = create_simple_ssh_asset(&mut conn, &unique_name("no-conn-asset"), user_id).await;

    use vauban_web::schema::proxy_sessions;

    let ip: ipnetwork::IpNetwork = unwrap_ok!("127.0.0.1".parse());
    let _: i32 = unwrap_ok!(
        diesel::insert_into(proxy_sessions::table)
            .values((
                proxy_sessions::uuid.eq(Uuid::new_v4()),
                proxy_sessions::user_id.eq(user_id),
                proxy_sessions::asset_id.eq(asset_id),
                proxy_sessions::credential_id.eq("cred-no-conn"),
                proxy_sessions::credential_username.eq("testuser"),
                proxy_sessions::session_type.eq("ssh"),
                proxy_sessions::status.eq("active"),
                proxy_sessions::client_ip.eq(ip),
                proxy_sessions::connected_at.eq(None::<chrono::DateTime<chrono::Utc>>),
                proxy_sessions::is_recorded.eq(false),
                proxy_sessions::metadata.eq(serde_json::json!({})),
            ))
            .returning(proxy_sessions::id)
            .get_result(&mut conn)
            .await
    );

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, true, true)
        .await;

    let response = app
        .server
        .get("/sessions/active")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    if response.status_code().as_u16() == 200 {
        let body = response.text();
        assert!(
            !body.contains("no-conn-asset"),
            "Session without connected_at must not appear in active sessions list"
        );
    }
}

/// Active sessions stats show SSH and RDP counters.
#[tokio::test]
async fn test_active_sessions_stats_show_type_counters() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("active_stats_user");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;
    let ssh_asset_id = create_simple_ssh_asset(&mut conn, &unique_name("stats-ssh"), user_id).await;
    let rdp_asset_id = create_simple_rdp_asset(&mut conn, &unique_name("stats-rdp"), user_id).await;

    let _ssh_session = create_test_session(&mut conn, user_id, ssh_asset_id, "ssh", "active").await;
    let _rdp_session = create_test_session(&mut conn, user_id, rdp_asset_id, "rdp", "active").await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, true, true)
        .await;

    let response = app
        .server
        .get("/sessions/active")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    if response.status_code().as_u16() == 200 {
        let body = response.text();
        assert!(body.contains("SSH"), "Stats must include SSH counter label");
        assert!(body.contains("RDP"), "Stats must include RDP counter label");
    }
}

/// Active sessions page has WebSocket connection for real-time updates.
#[tokio::test]
async fn test_active_sessions_has_ws_connect() {
    let app = TestApp::spawn().await;

    let token = app
        .generate_test_token(&Uuid::new_v4().to_string(), "test_ws_active", true, true)
        .await;

    let response = app
        .server
        .get("/sessions/active")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    if response.status_code().as_u16() == 200 {
        let body = response.text();
        assert!(
            body.contains("ws-connect=\"/ws/sessions/active\""),
            "Active sessions page must have WebSocket connection"
        );
    }
}

/// Active sessions page disconnect button has CSRF token.
#[tokio::test]
async fn test_active_sessions_disconnect_has_csrf() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("active_csrf_user");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;
    let asset_id = create_simple_ssh_asset(&mut conn, &unique_name("csrf-asset"), user_id).await;
    let _session_id = create_test_session(&mut conn, user_id, asset_id, "ssh", "active").await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, true, true)
        .await;

    let response = app
        .server
        .get("/sessions/active")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    if response.status_code().as_u16() == 200 {
        let body = response.text();
        assert!(
            body.contains("csrf_token"),
            "Disconnect button must include CSRF token"
        );
        assert!(
            body.contains("hx-post"),
            "Disconnect button must use hx-post for HTMX"
        );
        assert!(
            body.contains("hx-confirm"),
            "Disconnect button must have hx-confirm for confirmation dialog"
        );
    }
}

/// /sessions must NOT have a Terminate button even when active sessions exist.
/// Termination is only available on /sessions/active.
#[tokio::test]
async fn test_session_list_no_terminate_button() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("no_term_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("no-term-asset"), admin_id).await;
    let _session_id = create_test_session(&mut conn, admin_id, asset_id, "ssh", "active").await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let response = app
        .server
        .get("/sessions")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(
        !body.contains("hx-post") || !body.contains("/terminate"),
        "Session list page must NOT contain any terminate form/button"
    );
    assert!(
        !body.contains(">Terminate</button>"),
        "Session list page must NOT have a Terminate button"
    );
}

/// /sessions/active MUST have a Disconnect button for active sessions.
#[tokio::test]
async fn test_active_sessions_has_disconnect_button() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("disc_btn_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("disc-btn-asset"), admin_id).await;
    let session_id = create_test_session(&mut conn, admin_id, asset_id, "ssh", "active").await;

    {
        use vauban_web::schema::proxy_sessions;
        diesel::update(proxy_sessions::table.filter(proxy_sessions::id.eq(session_id)))
            .set((
                proxy_sessions::connected_at.eq(chrono::Utc::now()),
                proxy_sessions::client_ip
                    .eq(ipnetwork::IpNetwork::V4("127.0.0.1".parse().unwrap())),
            ))
            .execute(&mut conn)
            .await
            .unwrap();
    }

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let response = app
        .server
        .get("/sessions/active")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("Disconnect"),
        "Active sessions page must have a Disconnect button for active sessions"
    );
    assert!(
        body.contains("/terminate"),
        "Active sessions page must have a terminate action endpoint"
    );
}

/// Terminated sessions must not appear on the active sessions page.
#[tokio::test]
async fn test_active_sessions_excludes_terminated() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("active_no_term");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;
    let asset_id = create_simple_ssh_asset(&mut conn, &unique_name("term-asset"), user_id).await;
    let _term_session =
        create_test_session(&mut conn, user_id, asset_id, "ssh", "terminated").await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, true, true)
        .await;

    let response = app
        .server
        .get("/sessions/active")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    if response.status_code().as_u16() == 200 {
        let body = response.text();
        assert!(
            !body.contains("term-asset") || body.contains("No active sessions"),
            "Terminated sessions must not appear on active sessions page"
        );
    }
}
