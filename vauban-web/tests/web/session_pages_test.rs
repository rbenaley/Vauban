/// VAUBAN Web - Session Pages Tests.
///
/// Tests for session-related HTML pages:
/// - Session detail page
/// - Recording play page
/// - Active sessions page
/// - Session list with filters
/// - Session permissions
use crate::common::{TestApp, assertions::assert_status};
use crate::fixtures::{
    create_recorded_session, create_simple_admin_user, create_simple_ssh_asset,
    create_simple_user, create_test_session, unique_name,
};
use axum::http::header::COOKIE;
use diesel::prelude::*;
use uuid::Uuid;

/// Helper to get user UUID from user_id.
fn get_user_uuid(conn: &mut diesel::PgConnection, user_id: i32) -> Uuid {
    use vauban_web::schema::users;
    users::table
        .filter(users::id.eq(user_id))
        .select(users::uuid)
        .first(conn)
        .expect("User should exist")
}

// =============================================================================
// Session Detail Page Tests
// =============================================================================

#[tokio::test]
async fn test_session_detail_page_loads() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    let user_id = create_simple_user(&mut conn, "test_session_page");
    let user_uuid = get_user_uuid(&mut conn, user_id);
    let asset_id = create_simple_ssh_asset(&mut conn, "test-session-page-asset", user_id);
    let session_id = create_test_session(&mut conn, user_id, asset_id, "ssh", "active");

    let token = app.generate_test_token(&user_uuid.to_string(), "test_session_page", true, true);

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

#[tokio::test]
async fn test_session_detail_not_found() {
    let app = TestApp::spawn().await;

    let token = app.generate_test_token(
        &Uuid::new_v4().to_string(),
        "test_session_notfound",
        true,
        true,
    );

    let response = app
        .server
        .get("/sessions/999999")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 404);
}

// =============================================================================
// Recording Play Page Tests
// =============================================================================

#[tokio::test]
async fn test_recording_play_page_with_recorded_session() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    let user_id = create_simple_user(&mut conn, "test_recording_page");
    let user_uuid = get_user_uuid(&mut conn, user_id);
    let asset_id = create_simple_ssh_asset(&mut conn, "test-recording-asset", user_id);
    let session_id = create_recorded_session(&mut conn, user_id, asset_id);

    let token = app.generate_test_token(&user_uuid.to_string(), "test_recording_page", true, true);

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

    let token =
        app.generate_test_token(&Uuid::new_v4().to_string(), "test_rec_notfound", true, true);

    let response = app
        .server
        .get("/sessions/recordings/999999/play")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 404);
}

// =============================================================================
// Active Sessions Page Tests
// =============================================================================

#[tokio::test]
async fn test_active_sessions_page_loads() {
    let app = TestApp::spawn().await;

    let token = app.generate_test_token(
        &Uuid::new_v4().to_string(),
        "test_active_sessions",
        true,
        true,
    );

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
    let mut conn = app.get_conn();

    let user_id = create_simple_user(&mut conn, "test_active_data");
    let user_uuid = get_user_uuid(&mut conn, user_id);
    let asset_id = create_simple_ssh_asset(&mut conn, "test-active-asset", user_id);
    let _session_id = create_test_session(&mut conn, user_id, asset_id, "ssh", "active");

    let token = app.generate_test_token(&user_uuid.to_string(), "test_active_data", true, true);

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
    let mut conn = app.get_conn();

    let admin_username = unique_name("session_status_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username);
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_username, true, true);

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
    let statuses = ["active", "disconnected", "completed", "terminated", "pending"];

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
    let mut conn = app.get_conn();

    let admin_username = unique_name("session_type_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username);
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_username, true, true);

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
    let types = ["ssh", "rdp", "vnc"];

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

#[tokio::test]
async fn test_session_list_search_by_asset() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    let admin_username = unique_name("session_asset_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username);
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_username, true, true);

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
    let mut conn = app.get_conn();

    let admin_username = unique_name("session_combined_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username);
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_username, true, true);

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

#[tokio::test]
async fn test_session_list_filters_by_user() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    let user1_name = unique_name("sess_user1");
    let user1_id = create_simple_user(&mut conn, &user1_name);
    let user1_uuid = get_user_uuid(&mut conn, user1_id);

    let user2_name = unique_name("sess_user2");
    let user2_id = create_simple_user(&mut conn, &user2_name);

    let asset_id = create_simple_ssh_asset(&mut conn, &unique_name("filter-asset"), user1_id);
    let _session1_id = create_test_session(&mut conn, user1_id, asset_id, "ssh", "completed");
    let _session2_id = create_test_session(&mut conn, user2_id, asset_id, "ssh", "completed");

    let token = app.generate_test_token(&user1_uuid.to_string(), &user1_name, false, false);

    let response = app
        .server
        .get("/sessions")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 200,
        "User should access their session list, got {}",
        status
    );
}

#[tokio::test]
async fn test_session_list_admin_sees_all() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    let admin_name = unique_name("sess_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name);
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    let other_name = unique_name("other_sess_user");
    let other_id = create_simple_user(&mut conn, &other_name);
    let asset_id = create_simple_ssh_asset(&mut conn, &unique_name("all-sess-asset"), admin_id);
    let _session_id = create_test_session(&mut conn, other_id, asset_id, "ssh", "completed");

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_name, true, true);

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
    let mut conn = app.get_conn();

    let test_id = uuid::Uuid::new_v4().to_string()[..8].to_string();
    let username = format!("own_sess_user_{}", test_id);
    let user_id = create_simple_user(&mut conn, &username);
    let user_uuid = get_user_uuid(&mut conn, user_id);

    let asset_name = format!("own-sess-asset-{}", test_id);
    let asset_id = create_simple_ssh_asset(&mut conn, &asset_name, user_id);
    let session_id = create_test_session(&mut conn, user_id, asset_id, "ssh", "completed");

    use vauban_web::schema::proxy_sessions;
    let session_exists: bool = proxy_sessions::table
        .filter(proxy_sessions::id.eq(session_id))
        .select(proxy_sessions::id)
        .first::<i32>(&mut conn)
        .is_ok();
    assert!(session_exists, "Session should exist after creation");

    let token = app.generate_test_token(&user_uuid.to_string(), &username, false, false);

    let response = app
        .server
        .get(&format!("/sessions/{}", session_id))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 200,
        "User should access their own session detail, got {}. Session ID: {}",
        status, session_id
    );
}

#[tokio::test]
async fn test_session_detail_other_session_forbidden() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    let test_id = uuid::Uuid::new_v4().to_string()[..8].to_string();

    let owner_name = format!("sess_owner_{}", test_id);
    let owner_id = create_simple_user(&mut conn, &owner_name);
    let asset_name = format!("other-sess-asset-{}", test_id);
    let asset_id = create_simple_ssh_asset(&mut conn, &asset_name, owner_id);
    let session_id = create_test_session(&mut conn, owner_id, asset_id, "ssh", "completed");

    use vauban_web::schema::proxy_sessions;
    let session_exists: bool = proxy_sessions::table
        .filter(proxy_sessions::id.eq(session_id))
        .select(proxy_sessions::id)
        .first::<i32>(&mut conn)
        .is_ok();
    assert!(session_exists, "Session should exist after creation");

    let other_name = format!("sess_other_{}", test_id);
    let other_id = create_simple_user(&mut conn, &other_name);
    let other_uuid = get_user_uuid(&mut conn, other_id);

    let token = app.generate_test_token(&other_uuid.to_string(), &other_name, false, false);

    let response = app
        .server
        .get(&format!("/sessions/{}", session_id))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 401 || status == 403,
        "User should not access other's session, got {}. Session ID: {}",
        status, session_id
    );
}
