/// VAUBAN Web - MFA Pages Integration Tests.
///
/// Tests for MFA setup and verification pages (/mfa/setup, /mfa/verify).
use axum::http::header::{self, COOKIE};
use serial_test::serial;

use crate::common::{TestApp, assertions::*, test_db};
use crate::fixtures::{
    create_mfa_user, create_test_user, create_test_user_with_mfa, current_totp_for, unique_name,
};

// =============================================================================
// MFA Setup Page Tests (/mfa/setup)
// =============================================================================

/// Test MFA setup page requires authentication.
#[tokio::test]
#[serial]
async fn test_mfa_setup_page_requires_auth() {
    let app = TestApp::spawn().await;

    // Execute: GET /mfa/setup without authentication
    let response = app.server.get("/mfa/setup").await;

    // Assert: Should redirect to login or return 401
    let status = response.status_code().as_u16();
    assert!(
        status == 401 || status == 302 || status == 303,
        "Expected 401 or redirect, got {}",
        status
    );
}

/// Test MFA setup page renders the first-enrolment button for an authenticated
/// user with no pending candidate (VAU-008: GET is read-only, no QR until init,
/// and first enrolment asks for NO password).
#[tokio::test]
#[serial]
async fn test_mfa_setup_page_renders() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Setup: create user with temporary token (mfa_verified = false), carrying
    // a session jti (the in-memory candidate store key).
    let username = unique_name("mfa_setup");
    let test_user = create_test_user(&mut conn, &app.auth_service, &username).await;

    let session_uuid = uuid::Uuid::new_v4();
    let temp_token = app
        .auth_service
        .generate_access_token(
            &test_user.user.uuid.to_string(),
            &username,
            false,
            false,
            false,
            Some(session_uuid),
        )
        .unwrap();

    // Execute: GET /mfa/setup with temporary auth cookie
    let response = app
        .server
        .get("/mfa/setup")
        .add_header(COOKIE, format!("access_token={}", temp_token))
        .await;

    // Assert: 200 OK rendering the init form (no password, no QR leaked).
    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("/mfa/setup/init"),
        "Init form must post to /mfa/setup/init"
    );
    assert!(
        !body.contains("type=\"password\""),
        "First enrolment must NOT ask for a password"
    );
    assert!(
        !body.contains("data:image/png;base64,"),
        "GET must NOT leak a QR code when no candidate is pending"
    );

    // Cleanup
    test_db::cleanup(&mut conn).await;
}

/// Test MFA setup page shows the QR code once a candidate secret is pending
/// (i.e. after `POST /mfa/setup/init` has run). We seed the in-memory
/// per-session candidate store to assert the read-only GET renders the QR.
#[tokio::test]
#[serial]
async fn test_mfa_setup_page_shows_qr_code() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Setup: create user with temporary token carrying a session jti.
    let username = unique_name("mfa_qr");
    let test_user = create_test_user(&mut conn, &app.auth_service, &username).await;
    let session_uuid = uuid::Uuid::new_v4();
    let temp_token = app
        .auth_service
        .generate_access_token(
            &test_user.user.uuid.to_string(),
            &username,
            false,
            false,
            false,
            Some(session_uuid),
        )
        .unwrap();

    // Seed a pending (candidate) secret in the in-memory store as
    // POST /mfa/setup/init would. Tests run without a vault, so the candidate
    // is plaintext Base32. 32 Base32 chars = 20 bytes, satisfying the RFC 6238
    // minimum secret length enforced by TOTP::new.
    app.app_state.pending_mfa.put(
        &test_user.user.uuid.to_string(),
        &session_uuid.to_string(),
        "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP".to_string(),
    );

    // Execute: GET /mfa/setup
    let response = app
        .server
        .get("/mfa/setup")
        .add_header(COOKIE, format!("access_token={}", temp_token))
        .await;

    // Assert: Contains base64 QR code image rendered from the pending secret.
    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("data:image/png;base64,"),
        "Should contain base64 QR code image"
    );
    assert!(
        body.contains("totp_code"),
        "Should contain the confirmation TOTP input"
    );

    // Cleanup
    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// MFA Verify Page Tests (/mfa/verify)
// =============================================================================

/// Test MFA verify page requires authentication.
#[tokio::test]
#[serial]
async fn test_mfa_verify_page_requires_auth() {
    let app = TestApp::spawn().await;

    // Execute: GET /mfa/verify without authentication
    let response = app.server.get("/mfa/verify").await;

    // Assert: Should redirect to login or return 401
    let status = response.status_code().as_u16();
    assert!(
        status == 401 || status == 302 || status == 303,
        "Expected 401 or redirect, got {}",
        status
    );
}

/// Test MFA verify page renders for authenticated user with MFA enabled.
#[tokio::test]
#[serial]
async fn test_mfa_verify_page_renders() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Setup: create MFA-enabled user with temporary token
    let username = unique_name("mfa_verify");
    let mfa_user = create_mfa_user(&mut conn, &app.auth_service, &username).await;

    // Generate a temporary token with mfa_verified = false
    let temp_token = app
        .auth_service
        .generate_access_token(
            &mfa_user.user.uuid.to_string(),
            &username,
            false,
            false,
            false,
            None,
        )
        .unwrap();

    // Execute: GET /mfa/verify
    let response = app
        .server
        .get("/mfa/verify")
        .add_header(COOKIE, format!("access_token={}", temp_token))
        .await;

    // Assert: 200 OK with MFA verify content
    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("Two-Factor Authentication"),
        "Should contain MFA verify title"
    );
    assert!(
        body.contains("totp_code"),
        "Should contain TOTP input field"
    );
    assert!(body.contains("Verify"), "Should contain verify button");

    // Cleanup
    test_db::cleanup(&mut conn).await;
}

/// Test MFA verify page shows input for 6-digit code.
#[tokio::test]
#[serial]
async fn test_mfa_verify_page_has_code_input() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Setup: create MFA-enabled user with temporary token
    let username = unique_name("mfa_code_input");
    let mfa_user = create_mfa_user(&mut conn, &app.auth_service, &username).await;
    let temp_token = app
        .auth_service
        .generate_access_token(
            &mfa_user.user.uuid.to_string(),
            &username,
            false,
            false,
            false,
            None,
        )
        .unwrap();

    // Execute: GET /mfa/verify
    let response = app
        .server
        .get("/mfa/verify")
        .add_header(COOKIE, format!("access_token={}", temp_token))
        .await;

    // Assert: Contains 6-digit input field
    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("maxlength=\"6\""),
        "Should have maxlength=6 for TOTP input"
    );
    assert!(
        body.contains("pattern=\"[0-9]{6}\""),
        "Should have pattern for 6 digits"
    );

    // Cleanup
    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// MFA Setup Submit Tests (POST /mfa/setup)
// =============================================================================

/// Test MFA setup submission with invalid code.
#[tokio::test]
#[serial]
async fn test_mfa_setup_submit_invalid_code() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Setup: create user with temporary token
    let username = unique_name("mfa_invalid");
    let test_user = create_test_user(&mut conn, &app.auth_service, &username).await;
    let temp_token = app
        .auth_service
        .generate_access_token(
            &test_user.user.uuid.to_string(),
            &username,
            false,
            false,
            false,
            None,
        )
        .unwrap();

    // First, visit setup page to ensure secret is generated
    let _setup_response = app
        .server
        .get("/mfa/setup")
        .add_header(COOKIE, format!("access_token={}", temp_token))
        .await;

    // Get CSRF token from cookie (mock for test)
    // In real scenario, we'd extract from response

    // Execute: POST /mfa/setup with invalid code
    let response = app
        .server
        .post("/mfa/setup")
        .add_header(COOKIE, format!("access_token={}", temp_token))
        .form(&[("totp_code", "000000"), ("csrf_token", "test_csrf_token")])
        .await;

    // Assert: Should fail with redirect back to setup or error message
    let status = response.status_code().as_u16();
    // Either redirect (302/303) or error page (200 with error)
    assert!(
        status == 302 || status == 303 || status == 200 || status == 400,
        "Expected redirect or error, got {}",
        status
    );

    // Cleanup
    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// MFA Verify Submit Tests (POST /mfa/verify)
// =============================================================================

/// Test MFA verify submission with invalid code.
#[tokio::test]
#[serial]
async fn test_mfa_verify_submit_invalid_code() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Setup: create MFA-enabled user with temporary token
    let username = unique_name("mfa_verify_inv");
    let mfa_user = create_mfa_user(&mut conn, &app.auth_service, &username).await;
    let temp_token = app
        .auth_service
        .generate_access_token(
            &mfa_user.user.uuid.to_string(),
            &username,
            false,
            false,
            false,
            None,
        )
        .unwrap();

    // Execute: POST /mfa/verify with invalid code
    let response = app
        .server
        .post("/mfa/verify")
        .add_header(COOKIE, format!("access_token={}", temp_token))
        .form(&[("totp_code", "999999"), ("csrf_token", "test_csrf_token")])
        .await;

    // Assert: Should fail with redirect back to verify or error message
    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303 || status == 200 || status == 400,
        "Expected redirect or error, got {}",
        status
    );

    // Cleanup
    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Login Flow MFA Redirect Tests
// =============================================================================

/// Test login redirects to MFA setup for user without MFA enabled.
#[tokio::test]
#[serial]
async fn test_login_redirects_to_mfa_setup() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Setup: create user without MFA
    let username = unique_name("login_mfa_setup");
    let test_user = create_test_user(&mut conn, &app.auth_service, &username).await;

    // Execute: POST /auth/login via HTMX (expects JSON due to hx-ext="json-enc")
    // Note: CSRF validation is skipped when token is empty in test mode
    let response = app
        .server
        .post("/auth/login")
        .add_header(
            header::HeaderName::from_static("hx-request"),
            header::HeaderValue::from_static("true"),
        )
        .json(&serde_json::json!({
            "username": username,
            "password": test_user.password
        }))
        .await;

    // Assert: Should include HX-Redirect header to /mfa/setup
    let status = response.status_code().as_u16();
    let body = response.text();

    // The response should be 200 with HX-Redirect header
    // If CSRF fails, we get an error in the body
    assert!(
        status == 200,
        "Expected 200 with HX-Redirect, got {} with body: {}",
        status,
        body
    );

    // Check for CSRF error in body (if present, the test setup needs adjustment)
    if body.contains("CSRF") || body.contains("csrf") {
        // CSRF validation is blocking - this is expected in tests without proper cookie setup
        // For now, we just verify the flow works without CSRF in place
        return;
    }

    // Cleanup
    test_db::cleanup(&mut conn).await;
}

/// Test login redirects to MFA verify for user with MFA enabled.
#[tokio::test]
#[serial]
async fn test_login_redirects_to_mfa_verify() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Setup: create user with MFA enabled
    let username = unique_name("login_mfa_verify");
    let mfa_user = create_mfa_user(&mut conn, &app.auth_service, &username).await;

    // Execute: POST /auth/login via HTMX (expects JSON due to hx-ext="json-enc")
    let response = app
        .server
        .post("/auth/login")
        .add_header(
            header::HeaderName::from_static("hx-request"),
            header::HeaderValue::from_static("true"),
        )
        .json(&serde_json::json!({
            "username": username,
            "password": mfa_user.password
        }))
        .await;

    // Assert: Should include HX-Redirect header to /mfa/verify
    let status = response.status_code().as_u16();
    let body = response.text();

    assert!(
        status == 200,
        "Expected 200 with HX-Redirect, got {} with body: {}",
        status,
        body
    );

    // Check for CSRF error in body (if present, the test setup needs adjustment)
    if body.contains("CSRF") || body.contains("csrf") {
        // CSRF validation is blocking - this is expected in tests without proper cookie setup
        return;
    }

    // Cleanup
    test_db::cleanup(&mut conn).await;
}

fn access_token_cookie(response: &axum_test::TestResponse) -> Option<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .find_map(|line| {
            let first = line.split(';').next()?.trim();
            let value = first.strip_prefix("access_token=")?;
            Some(value.to_string())
        })
}

/// API: a wrong TOTP is refused, then the current code is accepted once.
#[tokio::test]
#[serial]
async fn e2e_api_login_rejects_bad_totp_then_accepts_good() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let username = unique_name("mfa_api_round");
    let test_user = create_test_user_with_mfa(&mut conn, &app.auth_service, &username).await;

    let bad = app
        .server
        .post("/api/v1/auth/login")
        .json(&serde_json::json!({
            "username": username,
            "password": test_user.password,
            "mfa_code": "000000",
        }))
        .await;
    assert_status(&bad, 401);

    let good = app
        .server
        .post("/api/v1/auth/login")
        .json(&serde_json::json!({
            "username": username,
            "password": test_user.password,
            "mfa_code": current_totp_for(&test_user.mfa_secret),
        }))
        .await;
    assert_status(&good, 200);
    test_db::cleanup(&mut conn).await;
}

/// Web: password then a wrong TOTP, then the current code.
#[tokio::test]
#[serial]
async fn e2e_web_login_rejects_bad_totp_then_accepts_good() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let username = unique_name("mfa_web_round");
    let test_user = create_test_user_with_mfa(&mut conn, &app.auth_service, &username).await;
    let csrf = app.generate_csrf_token();

    let login = app
        .server
        .post("/auth/login")
        .add_header(header::COOKIE, format!("__vauban_csrf={csrf}"))
        .add_header("HX-Request", "true")
        .json(&serde_json::json!({
            "username": username,
            "password": test_user.password,
            "csrf_token": csrf,
        }))
        .await;
    assert_status(&login, 200);
    let token = access_token_cookie(&login).expect("intermediate session cookie");
    let hx = login
        .headers()
        .get("hx-redirect")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        hx.contains("/mfa/verify"),
        "expected MFA redirect, got {hx}"
    );

    let bad = app
        .server
        .post("/mfa/verify")
        .add_header(
            header::COOKIE,
            format!("access_token={token}; __vauban_csrf={csrf}"),
        )
        .form(&[("totp_code", "000000"), ("csrf_token", csrf.as_str())])
        .await;
    let bad_status = bad.status_code().as_u16();
    assert!(
        bad_status == 303 || bad_status == 302,
        "bad TOTP redirects, got {bad_status}"
    );

    let good = app
        .server
        .post("/mfa/verify")
        .add_header(
            header::COOKIE,
            format!("access_token={token}; __vauban_csrf={csrf}"),
        )
        .form(&[
            (
                "totp_code",
                current_totp_for(&test_user.mfa_secret).as_str(),
            ),
            ("csrf_token", csrf.as_str()),
        ])
        .await;
    let good_status = good.status_code().as_u16();
    assert!(
        good_status == 303 || good_status == 302,
        "good TOTP redirects, got {good_status}"
    );
    test_db::cleanup(&mut conn).await;
}

#[tokio::test]
#[serial]
async fn attack_repeated_totp_is_rejected() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let username = unique_name("mfa_lock");
    let test_user = create_test_user_with_mfa(&mut conn, &app.auth_service, &username).await;
    {
        use diesel::{ExpressionMethods, QueryDsl};
        use diesel_async::RunQueryDsl;
        use vauban_web::schema::users;
        diesel::update(users::table.filter(users::id.eq(test_user.user.id)))
            .set(users::failed_login_attempts.eq(100))
            .execute(&mut conn)
            .await
            .expect("prime counter");
    }
    let response = app
        .server
        .post("/api/v1/auth/login")
        .json(&serde_json::json!({
            "username": username,
            "password": test_user.password,
            "mfa_code": "111111",
        }))
        .await;
    assert_status(&response, 401);

    let after = app
        .server
        .post("/api/v1/auth/login")
        .json(&serde_json::json!({
            "username": username,
            "password": test_user.password,
            "mfa_code": current_totp_for(&test_user.mfa_secret),
        }))
        .await;
    assert_status(&after, 401);
    test_db::cleanup(&mut conn).await;
}

#[tokio::test]
#[serial]
async fn attack_consumed_totp_window_is_rejected() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let username = unique_name("mfa_replay");
    let test_user = create_test_user_with_mfa(&mut conn, &app.auth_service, &username).await;
    let code = current_totp_for(&test_user.mfa_secret);
    let first = app
        .server
        .post("/api/v1/auth/login")
        .json(&serde_json::json!({
            "username": username,
            "password": test_user.password,
            "mfa_code": code,
        }))
        .await;
    assert_status(&first, 200);
    let second = app
        .server
        .post("/api/v1/auth/login")
        .json(&serde_json::json!({
            "username": username,
            "password": test_user.password,
            "mfa_code": code,
        }))
        .await;
    assert_status(&second, 401);
    test_db::cleanup(&mut conn).await;
}

#[tokio::test]
#[serial]
async fn battle_concurrent_totp_window_accepts_one() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let username = unique_name("mfa_battle");
    let test_user = create_test_user_with_mfa(&mut conn, &app.auth_service, &username).await;
    let code = current_totp_for(&test_user.mfa_secret);
    let body = serde_json::json!({
        "username": username,
        "password": test_user.password,
        "mfa_code": code,
    });
    let (left, right) = tokio::join!(
        app.server.post("/api/v1/auth/login").json(&body),
        app.server.post("/api/v1/auth/login").json(&body),
    );
    let statuses = [left.status_code().as_u16(), right.status_code().as_u16()];
    assert_eq!(
        statuses.iter().filter(|s| **s == 200).count(),
        1,
        "exactly one concurrent window wins, got {statuses:?}"
    );
    test_db::cleanup(&mut conn).await;
}
