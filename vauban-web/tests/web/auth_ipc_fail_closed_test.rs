//! Login with and without the auth IPC stub.
//!
//! The default [`TestApp`] attaches the in-process auth service, so a
//! local login still verifies. An app built with `auth_ipc_client: None`
//! must answer 500 on that same path and must not hash locally.

use axum::http::StatusCode;

use crate::common::TestApp;
use crate::fixtures::{create_test_user, create_test_user_with_mfa, current_totp_for, unique_name};

#[tokio::test]
async fn local_password_fallback_is_rejected() {
    let app = TestApp::spawn_without_auth_ipc().await;
    let mut conn = app.get_conn().await;
    let username = unique_name("no_auth_ipc");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;

    let response = app
        .server
        .post("/api/v1/auth/login")
        .json(&serde_json::json!({
            "username": username,
            "password": user.password,
        }))
        .await;

    assert_eq!(
        response.status_code(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "login without an auth IPC client must fail closed, body: {}",
        response.text()
    );
}

#[tokio::test]
async fn login_with_auth_stub_still_succeeds() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let username = unique_name("auth_stub_login");
    let user = create_test_user_with_mfa(&mut conn, &app.auth_service, &username).await;

    let response = app
        .server
        .post("/api/v1/auth/login")
        .json(&serde_json::json!({
            "username": username,
            "password": user.password,
            "mfa_code": current_totp_for(&user.mfa_secret),
        }))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 303,
        "login through the auth stub should succeed, got {status}, body: {}",
        response.text()
    );
}
