//! VAU-008 (ephemeral variant) E2E regression tests.
//!
//! These exercise the REAL HTTP surface (handlers + routing + CSRF) plus the
//! production in-memory candidate store (`AppState::pending_mfa`) against a
//! Postgres test database. They pin the revised invariants behaviourally:
//!
//! * INV-1 (zero persistence before confirmation) -- the candidate is NEVER
//!   written to `users`; GET is side-effect free; `mfa_secret` is promoted
//!   only by a confirmed `POST /mfa/setup`.
//! * INV-2 (isolation per session) -- two login sessions of the SAME account
//!   get distinct candidates (the core bug this fixes).
//! * INV-3 (generation gated) -- a secret is (re)generated ONLY by
//!   `POST /mfa/setup/init` behind CSRF; first enrolment needs NO password,
//!   rotation requires a valid CURRENT TOTP code.
//! * INV-4 -- exercised by the audit-instrumentation pins; here we assert the
//!   user-visible state transitions.

use axum::http::header::COOKIE;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use serial_test::serial;
use vauban_web::schema::users;
use vauban_web::services::auth::AuthService;

use crate::common::{TestApp, test_db};
use crate::fixtures::{create_test_user, current_totp_for, unique_name};

/// `(mfa_secret, mfa_enabled)` for a user id. There is no longer any
/// `pending_*` column: the candidate lives only in memory.
async fn read_state(
    conn: &mut vauban_web::db::DbConnection,
    user_id: i32,
) -> (Option<String>, bool) {
    users::table
        .filter(users::id.eq(user_id))
        .select((users::mfa_secret, users::mfa_enabled))
        .first(conn)
        .await
        .expect("user row must exist")
}

/// A pre-MFA (mfa_verified = false) bearer token carrying a session `jti`, plus
/// that `jti` string (the in-memory candidate store key). The `/mfa/setup`
/// handlers authenticate from the raw cookie only.
fn pre_mfa_session(app: &TestApp, uuid: &str, username: &str) -> (String, String) {
    let session_uuid = uuid::Uuid::new_v4();
    let token = app
        .auth_service
        .generate_access_token(uuid, username, false, false, false, Some(session_uuid))
        .expect("token generation must succeed");
    (token, session_uuid.to_string())
}

/// Enable MFA on an existing user with a KNOWN plaintext secret, so the test
/// can compute the current TOTP code (rotation step-up).
async fn enable_mfa_with_known_secret(
    conn: &mut vauban_web::db::DbConnection,
    user_id: i32,
    username: &str,
) -> String {
    let (secret, _) = AuthService::generate_totp_secret(username, "VAUBAN").unwrap();
    diesel::update(users::table.filter(users::id.eq(user_id)))
        .set((
            users::mfa_enabled.eq(true),
            users::mfa_secret.eq(Some(&secret)),
        ))
        .execute(conn)
        .await
        .unwrap();
    secret
}

// ---------------------------------------------------------------------------
// INV-1: GET is side-effect free
// ---------------------------------------------------------------------------

/// Repeated GETs on a fresh account never generate or persist a secret; the
/// page renders the "Configure 2FA" button (first enrolment), not a QR, and
/// asks for NO password.
#[tokio::test]
#[serial]
async fn get_setup_is_side_effect_free() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("vau008_get_pure");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;
    let (token, jti) = pre_mfa_session(app, &user.user.uuid.to_string(), &username);

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
            "GET must not render a QR with no pending candidate"
        );
        assert!(
            body.contains("/mfa/setup/init"),
            "GET must render the init form"
        );
        assert!(
            !body.contains("type=\"password\""),
            "first enrolment must NOT ask for a password"
        );
    }

    let (mfa_secret, mfa_enabled) = read_state(&mut conn, user.user.id).await;
    assert!(mfa_secret.is_none(), "mfa_secret must stay NULL after GETs");
    assert!(!mfa_enabled, "mfa_enabled must stay false after GETs");
    assert!(
        app.app_state
            .pending_mfa
            .get(&user.user.uuid.to_string(), &jti)
            .is_none(),
        "GET must not create a candidate"
    );

    test_db::cleanup(&mut conn).await;
}

// ---------------------------------------------------------------------------
// INV-3 (gating) + UX: first enrolment needs no password
// ---------------------------------------------------------------------------

/// First enrolment: the GET renders a button (no password field), a single
/// CSRF-only POST generates a candidate (in memory only), and the next GET
/// renders the QR. `mfa_secret` stays NULL throughout.
#[tokio::test]
#[serial]
async fn first_enrollment_needs_no_password() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("vau008_first_enrol");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;
    let uuid = user.user.uuid.to_string();
    let (token, jti) = pre_mfa_session(app, &uuid, &username);
    let csrf = app.generate_csrf_token();

    // POST init with ONLY a CSRF token (no password field at all).
    let response = app
        .server
        .post("/mfa/setup/init")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf),
        )
        .form(&[("csrf_token", csrf.as_str())])
        .await;
    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "expected redirect, got {status}"
    );

    // Candidate exists in memory, but nothing is persisted.
    assert!(
        app.app_state.pending_mfa.get(&uuid, &jti).is_some(),
        "init must create an in-memory candidate"
    );
    let (mfa_secret, mfa_enabled) = read_state(&mut conn, user.user.id).await;
    assert!(mfa_secret.is_none(), "init must NOT touch mfa_secret");
    assert!(!mfa_enabled, "init must NOT enable MFA");

    // The subsequent GET now renders the QR.
    let response = app
        .server
        .get("/mfa/setup")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_eq!(response.status_code().as_u16(), 200);
    assert!(
        response.text().contains("data:image/png;base64,"),
        "GET after init must render the QR from the in-memory candidate"
    );

    test_db::cleanup(&mut conn).await;
}

// ---------------------------------------------------------------------------
// INV-2: isolation per session (the core bug)
// ---------------------------------------------------------------------------

/// Two distinct login sessions of the SAME account obtain DIFFERENT candidate
/// secrets. This is the crux of the reported issue: a secret shown to one
/// session (e.g. the admin who created the account) must never be the one
/// offered to another session (the legitimate user).
#[tokio::test]
#[serial]
async fn two_sessions_get_different_secrets() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("vau008_two_sessions");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;
    let uuid = user.user.uuid.to_string();

    let (token1, jti1) = pre_mfa_session(app, &uuid, &username);
    let (token2, jti2) = pre_mfa_session(app, &uuid, &username);
    assert_ne!(jti1, jti2, "two logins must yield distinct sessions");
    let csrf = app.generate_csrf_token();

    for token in [&token1, &token2] {
        let response = app
            .server
            .post("/mfa/setup/init")
            .add_header(
                COOKIE,
                format!("access_token={}; __vauban_csrf={}", token, csrf),
            )
            .form(&[("csrf_token", csrf.as_str())])
            .await;
        let status = response.status_code().as_u16();
        assert!(status == 302 || status == 303);
    }

    let secret1 = app
        .app_state
        .pending_mfa
        .get(&uuid, &jti1)
        .expect("session 1 candidate");
    let secret2 = app
        .app_state
        .pending_mfa
        .get(&uuid, &jti2)
        .expect("session 2 candidate");
    assert_ne!(
        secret1, secret2,
        "each session must get an independent candidate secret"
    );

    test_db::cleanup(&mut conn).await;
}

// ---------------------------------------------------------------------------
// INV-1: candidate never persisted
// ---------------------------------------------------------------------------

/// After init, the candidate is exclusively in memory: `mfa_secret` is NULL and
/// `mfa_enabled` is false, and no row carries the candidate.
#[tokio::test]
#[serial]
async fn candidate_never_persisted() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("vau008_not_persisted");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;
    let uuid = user.user.uuid.to_string();
    let (token, jti) = pre_mfa_session(app, &uuid, &username);
    let csrf = app.generate_csrf_token();

    let response = app
        .server
        .post("/mfa/setup/init")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf),
        )
        .form(&[("csrf_token", csrf.as_str())])
        .await;
    assert!(matches!(response.status_code().as_u16(), 302 | 303));

    let candidate = app.app_state.pending_mfa.get(&uuid, &jti);
    assert!(candidate.is_some(), "candidate must be in the store");
    let (mfa_secret, mfa_enabled) = read_state(&mut conn, user.user.id).await;
    assert!(
        mfa_secret.is_none(),
        "candidate must never be persisted to mfa_secret"
    );
    assert!(!mfa_enabled);

    test_db::cleanup(&mut conn).await;
}

// ---------------------------------------------------------------------------
// INV-3: generation is gated by CSRF
// ---------------------------------------------------------------------------

/// A mismatched CSRF token rejects the init and generates nothing.
#[tokio::test]
#[serial]
async fn init_requires_csrf() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("vau008_init_csrf");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;
    let uuid = user.user.uuid.to_string();
    let (token, jti) = pre_mfa_session(app, &uuid, &username);
    let csrf = app.generate_csrf_token();

    let response = app
        .server
        .post("/mfa/setup/init")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf),
        )
        .form(&[("csrf_token", "not-the-cookie-token")])
        .await;
    assert!(matches!(response.status_code().as_u16(), 302 | 303));

    assert!(
        app.app_state.pending_mfa.get(&uuid, &jti).is_none(),
        "CSRF failure must not generate a candidate"
    );
    let (mfa_secret, _) = read_state(&mut conn, user.user.id).await;
    assert!(mfa_secret.is_none());

    test_db::cleanup(&mut conn).await;
}

// ---------------------------------------------------------------------------
// INV-3: rotation requires the current TOTP code
// ---------------------------------------------------------------------------

/// An already-enrolled user (rotation) must prove the CURRENT factor before a
/// new candidate is generated: missing/wrong code -> no candidate; valid
/// current code -> candidate generated.
#[tokio::test]
#[serial]
async fn rotation_requires_current_totp() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("vau008_rotation");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;
    let uuid = user.user.uuid.to_string();
    let current_secret = enable_mfa_with_known_secret(&mut conn, user.user.id, &username).await;
    let (token, jti) = pre_mfa_session(app, &uuid, &username);
    let csrf = app.generate_csrf_token();

    // (a) No code -> refused, no candidate.
    let response = app
        .server
        .post("/mfa/setup/init")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf),
        )
        .form(&[("csrf_token", csrf.as_str())])
        .await;
    assert!(matches!(response.status_code().as_u16(), 302 | 303));
    assert!(
        app.app_state.pending_mfa.get(&uuid, &jti).is_none(),
        "rotation without a current code must not generate a candidate"
    );

    // (b) Wrong code -> refused, no candidate.
    let response = app
        .server
        .post("/mfa/setup/init")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf),
        )
        .form(&[("csrf_token", csrf.as_str()), ("totp_code", "000000")])
        .await;
    assert!(matches!(response.status_code().as_u16(), 302 | 303));
    assert!(
        app.app_state.pending_mfa.get(&uuid, &jti).is_none(),
        "rotation with a wrong current code must not generate a candidate"
    );

    // (c) Valid current code -> candidate generated.
    let code = current_totp_for(&current_secret);
    let response = app
        .server
        .post("/mfa/setup/init")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf),
        )
        .form(&[("csrf_token", csrf.as_str()), ("totp_code", code.as_str())])
        .await;
    assert!(matches!(response.status_code().as_u16(), 302 | 303));
    let candidate = app.app_state.pending_mfa.get(&uuid, &jti);
    assert!(
        candidate.is_some(),
        "rotation with a valid current code must generate a candidate"
    );
    assert_ne!(
        candidate.as_deref(),
        Some(current_secret.as_str()),
        "the new candidate must differ from the active secret"
    );
    // The active secret must remain untouched until confirmation.
    let (mfa_secret, mfa_enabled) = read_state(&mut conn, user.user.id).await;
    assert_eq!(mfa_secret.as_deref(), Some(current_secret.as_str()));
    assert!(mfa_enabled);

    test_db::cleanup(&mut conn).await;
}

// ---------------------------------------------------------------------------
// INV-1: promotion happens only on a confirmed POST /mfa/setup
// ---------------------------------------------------------------------------

/// A wrong confirmation code leaves the candidate intact and never promotes it.
#[tokio::test]
#[serial]
async fn confirm_wrong_code_keeps_candidate() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("vau008_confirm_bad");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;
    let uuid = user.user.uuid.to_string();
    let (token, jti) = pre_mfa_session(app, &uuid, &username);
    let csrf = app.generate_csrf_token();
    let (secret, _) = AuthService::generate_totp_secret(&username, "VAUBAN").unwrap();
    app.app_state.pending_mfa.put(&uuid, &jti, secret.clone());

    let response = app
        .server
        .post("/mfa/setup")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf),
        )
        .form(&[("totp_code", "000000"), ("csrf_token", csrf.as_str())])
        .await;
    assert!(matches!(response.status_code().as_u16(), 302 | 303));

    let (mfa_secret, mfa_enabled) = read_state(&mut conn, user.user.id).await;
    assert!(mfa_secret.is_none(), "wrong code must not promote");
    assert!(!mfa_enabled);
    assert_eq!(
        app.app_state.pending_mfa.get(&uuid, &jti).as_deref(),
        Some(secret.as_str()),
        "candidate must be left intact after a wrong code"
    );

    test_db::cleanup(&mut conn).await;
}

/// A valid code promotes the candidate to `mfa_secret`, enables MFA, and evicts
/// the candidate from the store.
#[tokio::test]
#[serial]
async fn confirm_ok_promotes_candidate() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("vau008_confirm_ok");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;
    let uuid = user.user.uuid.to_string();
    let (token, jti) = pre_mfa_session(app, &uuid, &username);
    let csrf = app.generate_csrf_token();
    let (secret, _) = AuthService::generate_totp_secret(&username, "VAUBAN").unwrap();
    app.app_state.pending_mfa.put(&uuid, &jti, secret.clone());

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
    assert!(matches!(response.status_code().as_u16(), 302 | 303));

    let (mfa_secret, mfa_enabled) = read_state(&mut conn, user.user.id).await;
    assert_eq!(
        mfa_secret.as_deref(),
        Some(secret.as_str()),
        "confirm must promote the candidate to mfa_secret"
    );
    assert!(mfa_enabled, "confirm must enable MFA");
    assert!(
        app.app_state.pending_mfa.get(&uuid, &jti).is_none(),
        "confirm must evict the candidate from the store"
    );

    test_db::cleanup(&mut conn).await;
}

/// Confirming with no candidate in flight is a no-op redirect, never an enrol.
#[tokio::test]
#[serial]
async fn confirm_without_candidate_is_noop() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("vau008_confirm_nocand");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;
    let uuid = user.user.uuid.to_string();
    let (token, _jti) = pre_mfa_session(app, &uuid, &username);
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
    assert!(matches!(response.status_code().as_u16(), 302 | 303));

    let (mfa_secret, mfa_enabled) = read_state(&mut conn, user.user.id).await;
    assert!(mfa_secret.is_none());
    assert!(!mfa_enabled, "confirm without a candidate must not enrol");

    test_db::cleanup(&mut conn).await;
}

// ---------------------------------------------------------------------------
// INV-1 (post-MFA surface): /accounts/mfa is side-effect free (rotation entry)
// ---------------------------------------------------------------------------

/// `GET /accounts/mfa` (authenticated rotation surface) generates nothing,
/// never re-displays the enrolled secret, and renders the current-TOTP step-up
/// form (not a password prompt).
#[tokio::test]
#[serial]
async fn accounts_mfa_get_is_side_effect_free() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("vau008_accounts_mfa");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;
    let before_secret = enable_mfa_with_known_secret(&mut conn, user.user.id, &username).await;
    // mfa_verified token + DB session, required by the WebAuthUser extractor.
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
        "/accounts/mfa GET must not render a QR with no candidate"
    );
    assert!(
        body.contains("name=\"totp_code\""),
        "rotation must render the current-TOTP step-up form"
    );
    assert!(
        !body.contains("type=\"password\""),
        "rotation must NOT ask for a password"
    );

    let (mfa_secret, mfa_enabled) = read_state(&mut conn, user.user.id).await;
    assert_eq!(
        mfa_secret.as_deref(),
        Some(before_secret.as_str()),
        "/accounts/mfa GET must never mutate the enrolled secret"
    );
    assert!(mfa_enabled, "MFA stays enabled");

    test_db::cleanup(&mut conn).await;
}
