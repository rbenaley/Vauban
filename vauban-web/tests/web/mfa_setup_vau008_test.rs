//! VAU-008 E2E regression tests: `/mfa/setup` GET/POST split, pending secret,
//! and password step-up.
//!
//! These exercise the REAL HTTP surface (handlers + routing + CSRF) against a
//! Postgres test database. They pin the four VAU-008 invariants behaviourally:
//!
//! * INV-1 -- `GET /mfa/setup` and `GET /accounts/mfa` are side-effect free.
//! * INV-2 -- a secret is generated ONLY by `POST /mfa/setup/init`, behind CSRF
//!   and a password step-up.
//! * INV-3 -- generation writes ONLY `pending_mfa_secret`; `mfa_secret` is
//!   promoted exclusively by a confirmed `POST /mfa/setup`.
//! * INV-4 -- exercised by the audit-instrumentation pins; here we assert the
//!   user-visible state transitions.

use axum::http::header::COOKIE;
use chrono::{Duration, Utc};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use serial_test::serial;
use vauban_web::schema::users;
use vauban_web::services::auth::AuthService;

use crate::common::{TestApp, test_db};
use crate::fixtures::{create_mfa_user, create_test_user, current_totp_for, unique_name};

/// `(mfa_secret, mfa_enabled, pending_mfa_secret)` for a user id.
async fn read_state(
    conn: &mut vauban_web::db::DbConnection,
    user_id: i32,
) -> (Option<String>, bool, Option<String>) {
    users::table
        .filter(users::id.eq(user_id))
        .select((
            users::mfa_secret,
            users::mfa_enabled,
            users::pending_mfa_secret,
        ))
        .first(conn)
        .await
        .expect("user row must exist")
}

/// A pre-MFA (mfa_verified = false) bearer token for the user. The
/// `/mfa/setup` handlers authenticate from the raw cookie only.
fn pre_mfa_token(app: &TestApp, uuid: &str, username: &str) -> String {
    app.auth_service
        .generate_access_token(uuid, username, false, false, false, None)
        .expect("token generation must succeed")
}

// ---------------------------------------------------------------------------
// INV-1: GET is side-effect free
// ---------------------------------------------------------------------------

/// The crux of VAU-008: repeated GETs on a fresh account never generate or
/// persist a secret; the page renders the step-up form, not a QR.
#[tokio::test]
#[serial]
async fn get_setup_is_side_effect_free() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("vau008_get_pure");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;
    let token = pre_mfa_token(app, &user.user.uuid.to_string(), &username);

    for _ in 0..3 {
        let response = app
            .server
            .get("/mfa/setup")
            .add_header(COOKIE, format!("access_token={}", token))
            .await;
        assert_eq!(response.status_code().as_u16(), 200);
        let body = response.text();
        assert!(
            !body.contains("data:image/png;base64,"),
            "GET must not render a QR with no pending secret"
        );
        assert!(
            body.contains("/mfa/setup/init"),
            "GET must render the step-up form"
        );
    }

    let (mfa_secret, mfa_enabled, pending) = read_state(&mut conn, user.user.id).await;
    assert!(mfa_secret.is_none(), "mfa_secret must stay NULL after GETs");
    assert!(!mfa_enabled, "mfa_enabled must stay false after GETs");
    assert!(pending.is_none(), "pending must stay NULL after GETs");

    test_db::cleanup(&mut conn).await;
}

/// An already-enrolled secret is never disclosed or overwritten by a GET.
#[tokio::test]
#[serial]
async fn enrolled_user_get_never_overwrites() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("vau008_enrolled_get");
    let user = create_mfa_user(&mut conn, &app.auth_service, &username).await;
    let (before_secret, _, _) = read_state(&mut conn, user.user.id).await;
    let token = pre_mfa_token(app, &user.user.uuid.to_string(), &username);

    let response = app
        .server
        .get("/mfa/setup")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_eq!(response.status_code().as_u16(), 200);

    let (after_secret, _, pending) = read_state(&mut conn, user.user.id).await;
    assert_eq!(
        before_secret, after_secret,
        "GET must never mutate an enrolled mfa_secret"
    );
    assert!(pending.is_none(), "GET must not write a pending secret");

    test_db::cleanup(&mut conn).await;
}

// ---------------------------------------------------------------------------
// INV-2: generation is gated by CSRF + password step-up
// ---------------------------------------------------------------------------

/// A mismatched CSRF token rejects the init and generates nothing.
#[tokio::test]
#[serial]
async fn init_requires_csrf() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("vau008_init_csrf");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;
    let token = pre_mfa_token(app, &user.user.uuid.to_string(), &username);
    let csrf = app.generate_csrf_token();

    // Cookie CSRF differs from the body token -> double-submit fails.
    let response = app
        .server
        .post("/mfa/setup/init")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf),
        )
        .form(&[
            ("password", user.password.as_str()),
            ("csrf_token", "not-the-cookie-token"),
        ])
        .await;

    // Redirect back to setup, no generation.
    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "expected redirect, got {status}"
    );

    let (mfa_secret, _, pending) = read_state(&mut conn, user.user.id).await;
    assert!(mfa_secret.is_none());
    assert!(pending.is_none(), "CSRF failure must not generate a secret");

    test_db::cleanup(&mut conn).await;
}

/// A wrong password rejects the init and generates nothing.
#[tokio::test]
#[serial]
async fn init_wrong_password_no_generation() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("vau008_init_badpw");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;
    let token = pre_mfa_token(app, &user.user.uuid.to_string(), &username);
    let csrf = app.generate_csrf_token();

    let response = app
        .server
        .post("/mfa/setup/init")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf),
        )
        .form(&[
            ("password", "definitely-not-the-password"),
            ("csrf_token", csrf.as_str()),
        ])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "expected redirect, got {status}"
    );

    let (mfa_secret, _, pending) = read_state(&mut conn, user.user.id).await;
    assert!(mfa_secret.is_none());
    assert!(
        pending.is_none(),
        "wrong password must not generate a secret"
    );

    test_db::cleanup(&mut conn).await;
}

/// CSRF + correct password generate ONLY a pending secret (INV-3): mfa_secret
/// stays NULL and mfa_enabled stays false until a confirmed code.
#[tokio::test]
#[serial]
async fn init_ok_writes_pending_only() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("vau008_init_ok");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;
    let token = pre_mfa_token(app, &user.user.uuid.to_string(), &username);
    let csrf = app.generate_csrf_token();

    let response = app
        .server
        .post("/mfa/setup/init")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf),
        )
        .form(&[
            ("password", user.password.as_str()),
            ("csrf_token", csrf.as_str()),
        ])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "expected redirect, got {status}"
    );

    let (mfa_secret, mfa_enabled, pending) = read_state(&mut conn, user.user.id).await;
    assert!(pending.is_some(), "init must write a pending secret");
    assert!(mfa_secret.is_none(), "init must NOT touch mfa_secret");
    assert!(!mfa_enabled, "init must NOT enable MFA");

    test_db::cleanup(&mut conn).await;
}

/// Once a candidate is pending, the read-only GET renders its QR.
#[tokio::test]
#[serial]
async fn get_after_init_shows_qr() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("vau008_qr");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;
    let token = pre_mfa_token(app, &user.user.uuid.to_string(), &username);
    let (secret, _) = AuthService::generate_totp_secret(&username, "VAUBAN").unwrap();

    diesel::update(users::table.filter(users::id.eq(user.user.id)))
        .set((
            users::pending_mfa_secret.eq(Some(&secret)),
            users::pending_mfa_generated_at.eq(Some(Utc::now())),
        ))
        .execute(&mut conn)
        .await
        .unwrap();

    let response = app
        .server
        .get("/mfa/setup")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_eq!(response.status_code().as_u16(), 200);
    let body = response.text();
    assert!(
        body.contains("data:image/png;base64,"),
        "GET must render the QR from the pending secret"
    );

    test_db::cleanup(&mut conn).await;
}

// ---------------------------------------------------------------------------
// INV-3: promotion happens only on a confirmed POST /mfa/setup
// ---------------------------------------------------------------------------

/// A wrong confirmation code leaves the pending secret untouched and never
/// promotes it to mfa_secret.
#[tokio::test]
#[serial]
async fn confirm_wrong_code_keeps_pending() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("vau008_confirm_bad");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;
    let token = pre_mfa_token(app, &user.user.uuid.to_string(), &username);
    let csrf = app.generate_csrf_token();
    let (secret, _) = AuthService::generate_totp_secret(&username, "VAUBAN").unwrap();

    diesel::update(users::table.filter(users::id.eq(user.user.id)))
        .set((
            users::pending_mfa_secret.eq(Some(&secret)),
            users::pending_mfa_generated_at.eq(Some(Utc::now())),
        ))
        .execute(&mut conn)
        .await
        .unwrap();

    let response = app
        .server
        .post("/mfa/setup")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf),
        )
        .form(&[("totp_code", "000000"), ("csrf_token", csrf.as_str())])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "expected redirect, got {status}"
    );

    let (mfa_secret, mfa_enabled, pending) = read_state(&mut conn, user.user.id).await;
    assert!(
        mfa_secret.is_none(),
        "wrong code must not promote the secret"
    );
    assert!(!mfa_enabled);
    assert_eq!(
        pending.as_deref(),
        Some(secret.as_str()),
        "pending must be left intact"
    );

    test_db::cleanup(&mut conn).await;
}

/// A valid code promotes the pending secret to mfa_secret, enables MFA, and
/// clears the pending columns.
#[tokio::test]
#[serial]
async fn confirm_ok_promotes_pending() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("vau008_confirm_ok");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;
    let token = pre_mfa_token(app, &user.user.uuid.to_string(), &username);
    let csrf = app.generate_csrf_token();
    let (secret, _) = AuthService::generate_totp_secret(&username, "VAUBAN").unwrap();

    diesel::update(users::table.filter(users::id.eq(user.user.id)))
        .set((
            users::pending_mfa_secret.eq(Some(&secret)),
            users::pending_mfa_generated_at.eq(Some(Utc::now())),
        ))
        .execute(&mut conn)
        .await
        .unwrap();

    let code = current_totp_for(&secret);
    let response = app
        .server
        .post("/mfa/setup")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf),
        )
        .form(&[("totp_code", code.as_str()), ("csrf_token", csrf.as_str())])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "expected redirect, got {status}"
    );

    let (mfa_secret, mfa_enabled, pending) = read_state(&mut conn, user.user.id).await;
    assert_eq!(
        mfa_secret.as_deref(),
        Some(secret.as_str()),
        "confirm must promote the pending secret to mfa_secret"
    );
    assert!(mfa_enabled, "confirm must enable MFA");
    assert!(pending.is_none(), "confirm must clear the pending columns");

    test_db::cleanup(&mut conn).await;
}

/// A stale candidate (older than the TTL) is rejected on confirm and cleared.
#[tokio::test]
#[serial]
async fn stale_pending_rejected_on_confirm() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("vau008_stale");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;
    let token = pre_mfa_token(app, &user.user.uuid.to_string(), &username);
    let csrf = app.generate_csrf_token();
    let (secret, _) = AuthService::generate_totp_secret(&username, "VAUBAN").unwrap();

    // Generated well beyond the 15-minute TTL.
    diesel::update(users::table.filter(users::id.eq(user.user.id)))
        .set((
            users::pending_mfa_secret.eq(Some(&secret)),
            users::pending_mfa_generated_at.eq(Some(Utc::now() - Duration::minutes(30))),
        ))
        .execute(&mut conn)
        .await
        .unwrap();

    let code = current_totp_for(&secret);
    let response = app
        .server
        .post("/mfa/setup")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf),
        )
        .form(&[("totp_code", code.as_str()), ("csrf_token", csrf.as_str())])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "expected redirect, got {status}"
    );

    let (mfa_secret, mfa_enabled, pending) = read_state(&mut conn, user.user.id).await;
    assert!(mfa_secret.is_none(), "stale candidate must not be promoted");
    assert!(!mfa_enabled);
    assert!(pending.is_none(), "stale candidate must be cleared");

    test_db::cleanup(&mut conn).await;
}

/// Confirming with no pending candidate is a no-op redirect, never an enrol.
#[tokio::test]
#[serial]
async fn confirm_without_pending_is_noop() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("vau008_confirm_nopending");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;
    let token = pre_mfa_token(app, &user.user.uuid.to_string(), &username);
    let csrf = app.generate_csrf_token();

    let response = app
        .server
        .post("/mfa/setup")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf),
        )
        .form(&[("totp_code", "123456"), ("csrf_token", csrf.as_str())])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "expected redirect, got {status}"
    );

    let (mfa_secret, mfa_enabled, _) = read_state(&mut conn, user.user.id).await;
    assert!(mfa_secret.is_none());
    assert!(
        !mfa_enabled,
        "confirm without a pending secret must not enrol"
    );

    test_db::cleanup(&mut conn).await;
}

// ---------------------------------------------------------------------------
// INV-1 (post-MFA surface): /accounts/mfa is side-effect free too
// ---------------------------------------------------------------------------

/// `GET /accounts/mfa` (authenticated, post-login surface) generates nothing
/// and never re-displays or overwrites the already-enrolled secret.
#[tokio::test]
#[serial]
async fn accounts_mfa_get_is_side_effect_free() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // An MFA-enabled user so the dashboard posture check does not redirect to
    // /mfa/setup; generate_test_token issues an mfa_verified token + session,
    // which the WebAuthUser extractor on /accounts/mfa requires.
    let username = unique_name("vau008_accounts_mfa");
    let user = create_mfa_user(&mut conn, &app.auth_service, &username).await;
    let (before_secret, _, _) = read_state(&mut conn, user.user.id).await;
    let token = app
        .generate_test_token(&user.user.uuid.to_string(), &username, false, false)
        .await;

    let response = app
        .server
        .get("/accounts/mfa")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_eq!(response.status_code().as_u16(), 200);
    let body = response.text();
    assert!(
        !body.contains("data:image/png;base64,"),
        "/accounts/mfa GET must not render a QR with no pending secret"
    );

    let (mfa_secret, mfa_enabled, pending) = read_state(&mut conn, user.user.id).await;
    assert_eq!(
        before_secret, mfa_secret,
        "/accounts/mfa GET must never mutate the enrolled secret"
    );
    assert!(mfa_enabled, "MFA stays enabled");
    assert!(
        pending.is_none(),
        "/accounts/mfa GET must not write a pending secret"
    );

    test_db::cleanup(&mut conn).await;
}
