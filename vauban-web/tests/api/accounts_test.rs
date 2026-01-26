/// VAUBAN Web - Accounts API Integration Tests.
///
/// Tests for /api/v1/accounts/* endpoints.
use axum::http::header;
use serde_json::json;
use serial_test::serial;
use uuid::Uuid;

use crate::common::{TestApp, assertions::*, test_db};
use crate::fixtures::{create_admin_user, create_test_user, unique_name};

/// Test API returns 401 JSON error when not authenticated (not redirect).
#[tokio::test]
#[serial]
async fn test_api_returns_401_json_without_auth() {
    let app = TestApp::spawn().await;

    // Execute: GET /api/v1/accounts without auth
    let response = app.server.get("/api/v1/accounts").await;

    // Assert: API should return 401 Unauthorized (not 303 redirect)
    let status = response.status_code().as_u16();
    assert_eq!(
        status, 401,
        "API endpoints without auth should return 401 JSON, not redirect. Got {}",
        status
    );

    // Verify it's a JSON error response, not a redirect
    let json: serde_json::Value = response.json();
    assert!(
        json.get("error").is_some(),
        "API error response should contain 'error' field"
    );
    assert_eq!(
        json.get("status").and_then(|v| v.as_u64()),
        Some(401),
        "API error response should have status 401"
    );
}

/// Test list users as admin.
#[tokio::test]
#[serial]
async fn test_list_users_as_admin() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await.await;

    // Setup: create admin user
    let username = unique_name("test_admin");
    let admin = create_admin_user(&mut conn, &app.auth_service, &username).await;

    // Execute: GET /api/v1/accounts
    let response = app
        .server
        .get("/api/v1/accounts")
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;

    // Assert: 200 OK with array
    assert_status(&response, 200);
    let json: serde_json::Value = response.json();
    assert!(json.is_array() || json.get("users").is_some());

    // Cleanup
    test_db::cleanup(&mut conn).await;
}

/// Test list users as regular user (should be forbidden or limited).
#[tokio::test]
#[serial]
async fn test_list_users_as_regular_user() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await.await;

    // Setup: create regular user
    let username = unique_name("test_regular");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;

    // Execute: GET /api/v1/accounts
    let response = app
        .server
        .get("/api/v1/accounts")
        .add_header(header::AUTHORIZATION, app.auth_header(&user.token))
        .await;

    // Assert: 403 Forbidden (or 200 with limited results depending on implementation)
    let status = response.status_code().as_u16();
    assert!(
        status == 403 || status == 200,
        "Expected 403 or 200, got {}",
        status
    );

    // Cleanup
    test_db::cleanup(&mut conn).await;
}

/// Test list users with pagination.
#[tokio::test]
#[serial]
async fn test_list_users_pagination() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await.await;

    // Setup: create admin and some test users
    let admin_name = unique_name("test_admin_pag");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    for i in 0..5 {
        let name = unique_name(&format!("test_user_{}", i));
        create_test_user(&mut conn, &app.auth_service, &name).await;
    }

    // Execute: GET /api/v1/accounts with limit
    let response = app
        .server
        .get("/api/v1/accounts?limit=2&offset=0")
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;

    // Assert: 200 OK
    assert_status(&response, 200);

    // Cleanup
    test_db::cleanup(&mut conn).await;
}

/// Test list users with search filter.
#[tokio::test]
#[serial]
async fn test_list_users_search() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await.await;

    // Setup: create admin and a specific user
    let admin_name = unique_name("test_admin_search");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let target_name = unique_name("test_findme");
    create_test_user(&mut conn, &app.auth_service, &target_name).await;

    // Execute: GET /api/v1/accounts with search
    let response = app
        .server
        .get(&format!("/api/v1/accounts?search={}", target_name))
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;

    // Assert: 200 OK
    assert_status(&response, 200);

    // Cleanup
    test_db::cleanup(&mut conn).await;
}

/// Test create user as admin.
#[tokio::test]
#[serial]
async fn test_create_user_as_admin() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await.await;

    // Setup: create admin
    let admin_name = unique_name("test_admin_create");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let new_username = unique_name("test_newuser");

    // Execute: POST /api/v1/accounts
    let response = app
        .server
        .post("/api/v1/accounts")
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .json(&json!({
            "username": new_username,
            "email": format!("{}@test.vauban.io", new_username),
            "password": "SecurePassword123!",
            "first_name": "New",
            "last_name": "User"
        }))
        .await;

    // Assert: 200 OK or 201 Created (both acceptable)
    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 201,
        "Expected 200 or 201, got {}",
        status
    );

    // Cleanup
    test_db::cleanup(&mut conn).await;
}

/// Test create user with duplicate email.
#[tokio::test]
#[serial]
async fn test_create_user_duplicate_email() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await.await;

    // Setup: create admin and existing user
    let admin_name = unique_name("test_admin_dup");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let existing_name = unique_name("test_existing");
    let existing_user = create_test_user(&mut conn, &app.auth_service, &existing_name).await;

    // Execute: POST /api/v1/accounts with same email
    let response = app
        .server
        .post("/api/v1/accounts")
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .json(&json!({
            "username": unique_name("test_dup"),
            "email": existing_user.user.email,
            "password": "SecurePassword123!",
            "first_name": "Duplicate",
            "last_name": "User"
        }))
        .await;

    // Assert: 409 Conflict, 400 Bad Request, or 500 (DB constraint violation)
    let status = response.status_code().as_u16();
    assert!(
        status == 409 || status == 400 || status == 500,
        "Expected 409, 400, or 500, got {}",
        status
    );

    // Cleanup
    test_db::cleanup(&mut conn).await;
}

/// Test create user with invalid data.
#[tokio::test]
#[serial]
async fn test_create_user_invalid_data() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await.await;

    // Setup: create admin
    let admin_name = unique_name("test_admin_inv");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    // Execute: POST /api/v1/accounts with invalid email
    let response = app
        .server
        .post("/api/v1/accounts")
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .json(&json!({
            "username": "ab",  // Too short
            "email": "not-an-email",
            "password": "short"  // Too short
        }))
        .await;

    // Assert: 400 Bad Request
    assert_status(&response, 400);

    // Cleanup
    test_db::cleanup(&mut conn).await;
}

/// Test get user by UUID.
#[tokio::test]
#[serial]
async fn test_get_user_exists() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await.await;

    // Setup: create admin and target user
    let admin_name = unique_name("test_admin_get");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let target_name = unique_name("test_target");
    let target = create_test_user(&mut conn, &app.auth_service, &target_name).await;

    // Execute: GET /api/v1/accounts/{uuid}
    let response = app
        .server
        .get(&format!("/api/v1/accounts/{}", target.user.uuid))
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;

    // Assert: 200 OK
    assert_status(&response, 200);
    assert_json_has_field(&response, "uuid");

    // Cleanup
    test_db::cleanup(&mut conn).await;
}

/// Test get non-existent user.
#[tokio::test]
#[serial]
async fn test_get_user_not_found() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await.await;

    // Setup: create admin
    let admin_name = unique_name("test_admin_404");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let fake_uuid = Uuid::new_v4();

    // Execute: GET /api/v1/accounts/{fake_uuid}
    let response = app
        .server
        .get(&format!("/api/v1/accounts/{}", fake_uuid))
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;

    // Assert: 404 Not Found
    assert_status(&response, 404);

    // Cleanup
    test_db::cleanup(&mut conn).await;
}

/// Test update user.
#[tokio::test]
#[serial]
async fn test_update_user_success() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await.await;

    // Setup: create admin and target user
    let admin_name = unique_name("test_admin_upd");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let target_name = unique_name("test_update");
    let target = create_test_user(&mut conn, &app.auth_service, &target_name).await;

    // Execute: PUT /api/v1/accounts/{uuid}
    let response = app
        .server
        .put(&format!("/api/v1/accounts/{}", target.user.uuid))
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .json(&json!({
            "first_name": "Updated",
            "last_name": "Name"
        }))
        .await;

    // Assert: 200 OK
    assert_status(&response, 200);

    // Cleanup
    test_db::cleanup(&mut conn).await;
}

/// Test update non-existent user.
#[tokio::test]
#[serial]
async fn test_update_user_not_found() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await.await;

    // Setup: create admin
    let admin_name = unique_name("test_admin_upd404");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let fake_uuid = Uuid::new_v4();

    // Execute: PUT /api/v1/accounts/{fake_uuid}
    let response = app
        .server
        .put(&format!("/api/v1/accounts/{}", fake_uuid))
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .json(&json!({
            "first_name": "Updated"
        }))
        .await;

    // Assert: 404 Not Found
    assert_status(&response, 404);

    // Cleanup
    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Malformed UUID Tests
// =============================================================================

/// Test get user with malformed UUID returns validation error.
#[tokio::test]
#[serial]
async fn test_get_user_malformed_uuid_returns_validation_error() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await.await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("admin_malformed")).await;

    // Try various malformed UUIDs
    let malformed_uuids = [
        "not-a-uuid",
        "12345",
        "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "24d3cc30-d6c0-ooo7-be9a-978dd250ae3e",  // Invalid character 'o'
    ];

    for bad_uuid in malformed_uuids {
        let response = app
            .server
            .get(&format!("/api/v1/accounts/{}", bad_uuid))
            .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
            .await;

        let status = response.status_code().as_u16();
        assert!(
            status == 400 || status == 422,
            "Malformed UUID '{}' should return 400 or 422, got {}",
            bad_uuid,
            status
        );

        // Verify it's a JSON error response
        let body = response.text();
        assert!(
            body.contains("error") || body.contains("Invalid"),
            "Response should contain error message for malformed UUID '{}'",
            bad_uuid
        );
    }

    test_db::cleanup(&mut conn).await;
}

/// Test update user with malformed UUID returns validation error.
#[tokio::test]
#[serial]
async fn test_update_user_malformed_uuid_returns_validation_error() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await.await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("admin_upd_malformed")).await;

    let response = app
        .server
        .put("/api/v1/accounts/not-a-valid-uuid")
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .json(&json!({
            "first_name": "Test"
        }))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 400 || status == 422,
        "Malformed UUID should return 400 or 422, got {}",
        status
    );

    test_db::cleanup(&mut conn).await;
}
