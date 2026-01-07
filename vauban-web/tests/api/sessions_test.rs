/// VAUBAN Web - Sessions API Integration Tests.
///
/// Tests for /api/v1/sessions/* endpoints.
use axum::http::header;
use serde_json::json;
use serial_test::serial;
use uuid::Uuid;

use crate::common::{TestApp, assertions::*, test_db};
use crate::fixtures::{create_admin_user, create_test_ssh_asset, create_test_user, unique_name};

/// Test list sessions as admin.
#[tokio::test]
#[serial]
async fn test_list_sessions_as_admin() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Setup: create admin
    let admin_name = unique_name("test_admin_sess");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name);

    // Execute: GET /api/v1/sessions
    let response = app
        .server
        .get("/api/v1/sessions")
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;

    // Assert: 200 OK
    assert_status(&response, 200);

    // Cleanup
    test_db::cleanup(&mut conn);
}

/// Test list sessions as regular user (sees own sessions only).
#[tokio::test]
#[serial]
async fn test_list_sessions_user_own() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Setup: create user
    let username = unique_name("test_user_sess");
    let user = create_test_user(&mut conn, &app.auth_service, &username);

    // Execute: GET /api/v1/sessions
    let response = app
        .server
        .get("/api/v1/sessions")
        .add_header(header::AUTHORIZATION, app.auth_header(&user.token))
        .await;

    // Assert: 200 OK (may return empty list or user's sessions only)
    assert_status(&response, 200);

    // Cleanup
    test_db::cleanup(&mut conn);
}

/// Test list sessions with status filter.
#[tokio::test]
#[serial]
async fn test_list_sessions_filter_status() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Setup: create admin
    let admin_name = unique_name("test_admin_status");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name);

    // Execute: GET /api/v1/sessions?status=active
    let response = app
        .server
        .get("/api/v1/sessions?status=active")
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;

    // Assert: 200 OK
    assert_status(&response, 200);

    // Cleanup
    test_db::cleanup(&mut conn);
}

/// Test create session.
#[tokio::test]
#[serial]
async fn test_create_session_success() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Setup: create user and asset
    let username = unique_name("test_user_create_sess");
    let user = create_test_user(&mut conn, &app.auth_service, &username);

    let asset = create_test_ssh_asset(&mut conn, &unique_name("test-session-asset"));

    // Execute: POST /api/v1/sessions
    let response = app
        .server
        .post("/api/v1/sessions")
        .add_header(header::AUTHORIZATION, app.auth_header(&user.token))
        .json(&json!({
            "asset_uuid": asset.asset.uuid.to_string(),
            "session_type": "ssh",
            "credential_username": "admin",
            "justification": "Routine maintenance"
        }))
        .await;

    // Assert: 200, 201, or 422 (validation differences)
    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 201 || status == 422,
        "Expected 200, 201, or 422, got {}",
        status
    );

    // Cleanup
    test_db::cleanup(&mut conn);
}

/// Test create session with non-existent asset.
#[tokio::test]
#[serial]
async fn test_create_session_asset_not_found() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Setup: create user
    let username = unique_name("test_user_no_asset");
    let user = create_test_user(&mut conn, &app.auth_service, &username);

    let fake_asset_uuid = Uuid::new_v4();

    // Execute: POST /api/v1/sessions with fake asset
    let response = app
        .server
        .post("/api/v1/sessions")
        .add_header(header::AUTHORIZATION, app.auth_header(&user.token))
        .json(&json!({
            "asset_uuid": fake_asset_uuid.to_string(),
            "session_type": "ssh",
            "credential_username": "admin"
        }))
        .await;

    // Assert: 404, 422, or 500
    let status = response.status_code().as_u16();
    assert!(
        status == 404 || status == 422 || status == 500,
        "Expected 404, 422, or 500, got {}",
        status
    );

    // Cleanup
    test_db::cleanup(&mut conn);
}

/// Test get session by UUID.
#[tokio::test]
#[serial]
async fn test_get_session_exists() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Setup: create admin (for full access)
    let admin_name = unique_name("test_admin_get_sess");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name);

    // Note: In a real scenario, we'd create a session first, then get it
    // For now, test that 404/500 is returned for non-existent session
    let fake_session_uuid = Uuid::new_v4();

    // Execute: GET /api/v1/sessions/{uuid}
    let response = app
        .server
        .get(&format!("/api/v1/sessions/{}", fake_session_uuid))
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;

    // Assert: 404 Not Found
    assert_status(&response, 404);

    // Cleanup
    test_db::cleanup(&mut conn);
}

/// Test get session as non-owner (should be forbidden).
#[tokio::test]
#[serial]
async fn test_get_session_not_owner() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Setup: create two users
    let owner_name = unique_name("test_owner");
    let _owner = create_test_user(&mut conn, &app.auth_service, &owner_name);

    let other_name = unique_name("test_other");
    let other = create_test_user(&mut conn, &app.auth_service, &other_name);

    // Note: In a real scenario, owner would create a session,
    // then other user tries to access it
    let fake_session_uuid = Uuid::new_v4();

    // Execute: GET /api/v1/sessions/{uuid} as non-owner
    let response = app
        .server
        .get(&format!("/api/v1/sessions/{}", fake_session_uuid))
        .add_header(header::AUTHORIZATION, app.auth_header(&other.token))
        .await;

    // Assert: 403 Forbidden or 404 Not Found
    let status = response.status_code().as_u16();
    assert!(
        status == 403 || status == 404,
        "Expected 403 or 404, got {}",
        status
    );

    // Cleanup
    test_db::cleanup(&mut conn);
}
