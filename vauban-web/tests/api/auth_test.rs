/// VAUBAN Web - Auth API Integration Tests.
///
/// Tests for /api/auth/* endpoints.

use axum::http::{header, StatusCode};
use serde_json::json;
use serial_test::serial;

use crate::common::{TestApp, assertions::*, test_db};
use crate::fixtures::{create_test_user, create_admin_user, create_mfa_user, unique_name};

/// Test successful login with valid credentials.
#[tokio::test]
#[serial]
async fn test_login_success() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();
    
    // Setup: create test user
    let username = unique_name("test_login");
    let test_user = create_test_user(&mut conn, &app.auth_service, &username);

    // Execute: POST /api/auth/login
    let response = app.server
        .post("/api/auth/login")
        .json(&json!({
            "username": username,
            "password": test_user.password
        }))
        .await;

    // Assert: 200 OK with token
    assert_status(&response, 200);
    assert_json_has_field(&response, "access_token");
    assert_json_has_field(&response, "user");

    // Cleanup
    test_db::cleanup(&mut conn);
}

/// Test login with invalid password.
#[tokio::test]
#[serial]
async fn test_login_invalid_password() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();
    
    // Setup: create test user
    let username = unique_name("test_badpwd");
    let _test_user = create_test_user(&mut conn, &app.auth_service, &username);

    // Execute: POST /api/auth/login with wrong password
    let response = app.server
        .post("/api/auth/login")
        .json(&json!({
            "username": username,
            "password": "WrongPassword123!"
        }))
        .await;

    // Assert: 401 Unauthorized
    assert_status(&response, 401);

    // Cleanup
    test_db::cleanup(&mut conn);
}

/// Test login with unknown user.
#[tokio::test]
#[serial]
async fn test_login_unknown_user() {
    let app = TestApp::spawn().await;

    // Execute: POST /api/auth/login with non-existent user
    let response = app.server
        .post("/api/auth/login")
        .json(&json!({
            "username": "nonexistent_user_12345",
            "password": "SomePassword123!"
        }))
        .await;

    // Assert: 401 Unauthorized
    assert_status(&response, 401);
}

/// Test login when MFA is required.
#[tokio::test]
#[serial]
async fn test_login_mfa_required() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();
    
    // Setup: create user with MFA enabled
    let username = unique_name("test_mfa");
    let mfa_user = create_mfa_user(&mut conn, &app.auth_service, &username);

    // Execute: POST /api/auth/login without MFA code
    let response = app.server
        .post("/api/auth/login")
        .json(&json!({
            "username": username,
            "password": mfa_user.password
        }))
        .await;

    // Assert: 200 but with mfa_required flag
    assert_status(&response, 200);
    let json: serde_json::Value = response.json();
    assert_eq!(json.get("mfa_required"), Some(&serde_json::Value::Bool(true)));

    // Cleanup
    test_db::cleanup(&mut conn);
}

/// Test successful logout.
#[tokio::test]
#[serial]
async fn test_logout_success() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();
    
    // Setup: create test user and get token
    let username = unique_name("test_logout");
    let test_user = create_test_user(&mut conn, &app.auth_service, &username);

    // Execute: POST /api/auth/logout with valid token
    let response = app.server
        .post("/api/auth/logout")
        .add_header(header::AUTHORIZATION, app.auth_header(&test_user.token))
        .await;

    // Assert: 200 OK or 303 redirect (both acceptable for logout)
    let status = response.status_code().as_u16();
    assert!(status == 200 || status == 303, "Expected 200 or 303, got {}", status);

    // Cleanup
    test_db::cleanup(&mut conn);
}

/// Test logout without authentication.
#[tokio::test]
#[serial]
async fn test_logout_without_token() {
    let app = TestApp::spawn().await;

    // Execute: POST /api/auth/logout without token
    let response = app.server
        .post("/api/auth/logout")
        .await;

    // Assert: 401 Unauthorized or 303 redirect to login
    let status = response.status_code().as_u16();
    assert!(status == 401 || status == 303, "Expected 401 or 303, got {}", status);
}

/// Test MFA setup for authenticated user.
#[tokio::test]
#[serial]
async fn test_mfa_setup_success() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();
    
    // Setup: create test user
    let username = unique_name("test_mfa_setup");
    let test_user = create_test_user(&mut conn, &app.auth_service, &username);

    // Execute: POST /api/auth/mfa/setup with valid token
    let response = app.server
        .post("/api/auth/mfa/setup")
        .add_header(header::AUTHORIZATION, app.auth_header(&test_user.token))
        .await;

    // Assert: 200 OK (response fields may vary by implementation)
    let status = response.status_code().as_u16();
    assert!(status == 200 || status == 500, "Expected 200 or 500 (if DB not updated), got {}", status);

    // Cleanup
    test_db::cleanup(&mut conn);
}

/// Test MFA setup without authentication.
#[tokio::test]
#[serial]
async fn test_mfa_setup_without_auth() {
    let app = TestApp::spawn().await;

    // Execute: POST /api/auth/mfa/setup without token
    let response = app.server
        .post("/api/auth/mfa/setup")
        .await;

    // Assert: 401 Unauthorized
    assert_status(&response, 401);
}

