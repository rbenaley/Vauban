/// VAUBAN Web - Auth API Integration Tests.
///
/// Tests for /api/v1/auth/* endpoints.
use axum::http::header;
use serde_json::json;
use serial_test::serial;

use crate::common::{TestApp, assertions::*, test_db};
use crate::fixtures::{create_mfa_user, create_test_user, unique_name};

/// Test successful login with valid credentials.
#[tokio::test]
#[serial]
async fn test_login_success() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Setup: create test user
    let username = unique_name("test_login");
    let test_user = create_test_user(&mut conn, &app.auth_service, &username);

    // Execute: POST /api/v1/auth/login
    let response = app
        .server
        .post("/api/v1/auth/login")
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

    // Execute: POST /api/v1/auth/login with wrong password
    let response = app
        .server
        .post("/api/v1/auth/login")
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

    // Execute: POST /api/v1/auth/login with non-existent user
    let response = app
        .server
        .post("/api/v1/auth/login")
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

    // Execute: POST /api/v1/auth/login without MFA code
    let response = app
        .server
        .post("/api/v1/auth/login")
        .json(&json!({
            "username": username,
            "password": mfa_user.password
        }))
        .await;

    // Assert: 200 but with mfa_required flag
    assert_status(&response, 200);
    let json: serde_json::Value = response.json();
    assert_eq!(
        json.get("mfa_required"),
        Some(&serde_json::Value::Bool(true))
    );

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

    // Execute: POST /api/v1/auth/logout with valid token
    let response = app
        .server
        .post("/api/v1/auth/logout")
        .add_header(header::AUTHORIZATION, app.auth_header(&test_user.token))
        .await;

    // Assert: 200 OK or 303 redirect (both acceptable for logout)
    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 303,
        "Expected 200 or 303, got {}",
        status
    );

    // Cleanup
    test_db::cleanup(&mut conn);
}

/// Test logout without authentication.
#[tokio::test]
#[serial]
async fn test_logout_without_token() {
    let app = TestApp::spawn().await;

    // Execute: POST /api/v1/auth/logout without token
    let response = app.server.post("/api/v1/auth/logout").await;

    // Assert: 401 Unauthorized or 303 redirect to login
    let status = response.status_code().as_u16();
    assert!(
        status == 401 || status == 303,
        "Expected 401 or 303, got {}",
        status
    );
}

/// Test MFA setup page for authenticated user (web flow).
#[tokio::test]
#[serial]
async fn test_mfa_setup_page_success() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Setup: create test user with temporary token (mfa_verified = false)
    let username = unique_name("test_mfa_setup");
    let test_user = create_test_user(&mut conn, &app.auth_service, &username);
    let temp_token = app.auth_service
        .generate_access_token(&test_user.user.uuid.to_string(), &username, false, false, false)
        .unwrap();

    // Execute: GET /mfa/setup with cookie auth
    let response = app
        .server
        .get("/mfa/setup")
        .add_header(header::COOKIE, format!("access_token={}", temp_token))
        .await;

    // Assert: 200 OK with MFA setup page
    let status = response.status_code().as_u16();
    assert_eq!(status, 200, "MFA setup page should load, got {}", status);
    let body = response.text();
    assert!(body.contains("Two-Factor Authentication"), "Should show MFA setup page");

    // Cleanup
    test_db::cleanup(&mut conn);
}

/// Test MFA setup page without authentication.
#[tokio::test]
#[serial]
async fn test_mfa_setup_page_without_auth() {
    let app = TestApp::spawn().await;

    // Execute: GET /mfa/setup without auth cookie
    let response = app.server.get("/mfa/setup").await;

    // Assert: Should redirect to login or return 401
    let status = response.status_code().as_u16();
    assert!(
        status == 401 || status == 302 || status == 303,
        "Expected 401 or redirect, got {}",
        status
    );
}
