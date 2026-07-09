//! Global client IP ACL (`[security] allowed_client_networks`) -- E2E.
//!
//! Real HTTP through `build_test_router` with the production
//! `ip_acl_middleware` mounted before `auth_middleware` (exactly like
//! `main.rs` `common_layers`). Client IPs are simulated the same way as
//! `test_login_ignores_spoofed_xff_header`: the in-process TestServer has
//! no ConnectInfo so the middleware falls back to loopback as the TCP
//! peer; with `trusted_proxies = ["127.0.0.1", "::1"]` the
//! `X-Forwarded-For` header is honoured, so the header IS the simulated
//! client IP.
//!
//! Contract under test (stealth deny):
//! - allowed IP: everything works;
//! - denied IP: `POST` login returns the byte-identical generic
//!   "Invalid credentials" failure, every other request behaves exactly
//!   like an anonymous visitor's (login page served, 303 to /login on
//!   protected pages, 401 on the API) -- even with a VALID session
//!   cookie or API key;
//! - spoofed XFF without a trusted proxy: ignored (peer = loopback,
//!   always permitted -- anti-lockout);
//! - empty ACL: disabled, allow all.

use axum::http::header;
use axum::http::header::COOKIE;
use serde_json::json;

use crate::common::{TestApp, test_db, unwrap_ok};
use crate::fixtures::{create_test_user_with_mfa, current_totp_for, unique_name};

/// Simulated client IP inside `10.0.0.0/8` (allowed by `spawn_ip_acl`).
const ALLOWED_IP: &str = "10.1.2.3";
/// Simulated client IP inside the `/32` single-provider range.
const ALLOWED_PROVIDER_IP: &str = "104.28.30.3";
/// Simulated client IP outside every configured range.
const DENIED_IP: &str = "8.8.8.8";

fn xff(value: &str) -> header::HeaderValue {
    unwrap_ok!(value.parse::<header::HeaderValue>())
}

// =============================================================================
// Allowed IPs: nominal behaviour
// =============================================================================

/// A client inside `10.0.0.0/8` logs in end-to-end (API login with MFA).
#[tokio::test]
async fn login_succeeds_from_allowed_ip() {
    let app = TestApp::spawn_ip_acl().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("test_acl_ok");
    let user = create_test_user_with_mfa(&mut conn, &app.auth_service, &username).await;

    let response = app
        .server
        .post("/api/v1/auth/login")
        .add_header(
            header::HeaderName::from_static("x-forwarded-for"),
            xff(ALLOWED_IP),
        )
        .json(&json!({
            "username": username,
            "password": user.password,
            "mfa_code": current_totp_for(&user.mfa_secret),
        }))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 303,
        "login from an allowed IP must succeed, got {status}"
    );

    test_db::cleanup(&mut conn).await;
}

/// The `/32` single-provider range admits exactly its one address.
#[tokio::test]
async fn slash_32_provider_ip_is_allowed() {
    let app = TestApp::spawn_ip_acl().await;

    let response = app
        .server
        .get("/login")
        .add_header(
            header::HeaderName::from_static("x-forwarded-for"),
            xff(ALLOWED_PROVIDER_IP),
        )
        .await;
    assert_eq!(response.status_code().as_u16(), 200);
}

// =============================================================================
// Denied IPs: stealth contract
// =============================================================================

/// A denied IP submitting CORRECT credentials gets the byte-identical
/// response of an allowed IP submitting a WRONG password. This is the
/// core anti-enumeration guarantee: nothing in the response reveals
/// that an ACL exists.
#[tokio::test]
async fn denied_ip_login_is_byte_identical_to_wrong_password() {
    let app = TestApp::spawn_ip_acl().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("test_acl_stealth");
    let user = create_test_user_with_mfa(&mut conn, &app.auth_service, &username).await;

    // (A) denied IP, CORRECT credentials.
    let denied = app
        .server
        .post("/api/v1/auth/login")
        .add_header(
            header::HeaderName::from_static("x-forwarded-for"),
            xff(DENIED_IP),
        )
        .json(&json!({
            "username": username,
            "password": user.password,
            "mfa_code": current_totp_for(&user.mfa_secret),
        }))
        .await;

    // (B) allowed IP, WRONG password.
    let wrong_password = app
        .server
        .post("/api/v1/auth/login")
        .add_header(
            header::HeaderName::from_static("x-forwarded-for"),
            xff(ALLOWED_IP),
        )
        .json(&json!({
            "username": username,
            "password": "definitely-not-the-password-123",
            "mfa_code": current_totp_for(&user.mfa_secret),
        }))
        .await;

    assert_eq!(
        denied.status_code(),
        wrong_password.status_code(),
        "status must not distinguish ACL denial from bad credentials"
    );
    assert_eq!(
        denied.as_bytes(),
        wrong_password.as_bytes(),
        "body must be byte-identical between ACL denial and bad credentials"
    );

    test_db::cleanup(&mut conn).await;
}

/// Same stealth contract on the HTMX web login form (`POST /auth/login`
/// carries an HTML fragment, not JSON): identical fragment either way.
#[tokio::test]
async fn denied_ip_htmx_login_fragment_is_identical_to_wrong_password() {
    let app = TestApp::spawn_ip_acl().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("test_acl_htmx");
    let user = create_test_user_with_mfa(&mut conn, &app.auth_service, &username).await;

    let denied = app
        .server
        .post("/api/v1/auth/login")
        .add_header(
            header::HeaderName::from_static("x-forwarded-for"),
            xff(DENIED_IP),
        )
        .add_header(header::HeaderName::from_static("hx-request"), xff("true"))
        .json(&json!({
            "username": username,
            "password": user.password,
            "mfa_code": current_totp_for(&user.mfa_secret),
        }))
        .await;

    let wrong_password = app
        .server
        .post("/api/v1/auth/login")
        .add_header(
            header::HeaderName::from_static("x-forwarded-for"),
            xff(ALLOWED_IP),
        )
        .add_header(header::HeaderName::from_static("hx-request"), xff("true"))
        .json(&json!({
            "username": username,
            "password": "definitely-not-the-password-123",
            "mfa_code": current_totp_for(&user.mfa_secret),
        }))
        .await;

    assert_eq!(denied.status_code(), wrong_password.status_code());
    assert_eq!(
        denied.text(),
        wrong_password.text(),
        "HTMX fragment must be identical between ACL denial and bad credentials"
    );

    test_db::cleanup(&mut conn).await;
}

/// A VALID session cookie presented from a denied IP is treated as
/// anonymous: protected pages bounce to /login exactly like a
/// logged-out visitor (credential downgrade, not a distinctive 403).
#[tokio::test]
async fn valid_session_cookie_from_denied_ip_is_anonymous() {
    let app = TestApp::spawn_ip_acl().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("test_acl_cookie");
    let user = create_test_user_with_mfa(&mut conn, &app.auth_service, &username).await;

    // Control: the same cookie works from an allowed IP.
    // (`/accounts/login-sessions` is an authenticated page mounted in the
    // test router; `/dashboard` is not.)
    let allowed = app
        .server
        .get("/accounts/login-sessions")
        .add_header(COOKIE, format!("access_token={}", user.token))
        .add_header(
            header::HeaderName::from_static("x-forwarded-for"),
            xff(ALLOWED_IP),
        )
        .await;
    assert_eq!(
        allowed.status_code().as_u16(),
        200,
        "control: valid cookie from an allowed IP must reach the authenticated page"
    );

    // Denied IP: same cookie, anonymous behaviour (303 to /login).
    let denied = app
        .server
        .get("/accounts/login-sessions")
        .add_header(COOKIE, format!("access_token={}", user.token))
        .add_header(
            header::HeaderName::from_static("x-forwarded-for"),
            xff(DENIED_IP),
        )
        .await;
    assert_eq!(
        denied.status_code().as_u16(),
        303,
        "valid cookie from a denied IP must behave like an anonymous visitor"
    );
    let location = denied
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        location.starts_with("/login"),
        "anonymous downgrade must produce the ordinary /login redirect, got {location}"
    );

    test_db::cleanup(&mut conn).await;
}

/// Stealth: the public login page (and by extension the public surface)
/// is served normally to denied IPs -- a denied client sees a perfectly
/// ordinary bastion, not an error wall.
#[tokio::test]
async fn login_page_is_served_to_denied_ips() {
    let app = TestApp::spawn_ip_acl().await;

    let response = app
        .server
        .get("/login")
        .add_header(
            header::HeaderName::from_static("x-forwarded-for"),
            xff(DENIED_IP),
        )
        .await;
    assert_eq!(
        response.status_code().as_u16(),
        200,
        "the login page must be served normally to denied IPs (stealth)"
    );
}

/// The API zone from a denied IP behaves like an unauthenticated call
/// (401), even with a valid bearer token: the Authorization header is
/// stripped by the downgrade.
#[tokio::test]
async fn api_bearer_from_denied_ip_is_unauthenticated() {
    let app = TestApp::spawn_ip_acl().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("test_acl_api");
    let user = create_test_user_with_mfa(&mut conn, &app.auth_service, &username).await;

    let response = app
        .server
        .get("/api/v1/assets")
        .add_header(
            header::AUTHORIZATION,
            unwrap_ok!(format!("Bearer {}", user.token).parse::<header::HeaderValue>()),
        )
        .add_header(
            header::HeaderName::from_static("x-forwarded-for"),
            xff(DENIED_IP),
        )
        .await;
    assert_eq!(
        response.status_code().as_u16(),
        401,
        "a denied IP must get the ordinary unauthenticated 401 on the API"
    );

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Spoofing resistance + loopback bypass
// =============================================================================

/// Without a trusted proxy, `X-Forwarded-For` is ignored: the request is
/// attributed to the loopback TCP peer, which the matcher ALWAYS permits
/// (anti-lockout rescue). An attacker cannot deny (or grant) themselves
/// an IP by forging the header.
#[tokio::test]
async fn spoofed_xff_is_ignored_without_trusted_proxy() {
    let app = TestApp::spawn_ip_acl_untrusted_xff().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("test_acl_spoof");
    let user = create_test_user_with_mfa(&mut conn, &app.auth_service, &username).await;

    // The forged "denied" XFF changes nothing: peer is loopback.
    let response = app
        .server
        .get("/accounts/login-sessions")
        .add_header(COOKIE, format!("access_token={}", user.token))
        .add_header(
            header::HeaderName::from_static("x-forwarded-for"),
            xff(DENIED_IP),
        )
        .await;
    assert_eq!(
        response.status_code().as_u16(),
        200,
        "XFF from an untrusted peer must be ignored (peer loopback is always permitted)"
    );

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Disabled ACL (empty list): backward compatible allow-all
// =============================================================================

/// The default TestApp has `allowed_client_networks = []`: the ACL is
/// disabled and every existing flow is untouched.
#[tokio::test]
async fn empty_acl_allows_everything() {
    let app = TestApp::spawn().await;

    let response = app.server.get("/login").await;
    assert_eq!(
        response.status_code().as_u16(),
        200,
        "empty ACL must be a no-op (allow all)"
    );
}
