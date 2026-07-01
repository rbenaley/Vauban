//! E2E tests for the privilege-revocation contract.
//!
//! A login session must never outlive the privileges (or credential) it
//! was minted with. Two independent layers enforce this -- both are
//! exercised here:
//!
//! - **Layer A (invariant, fail-closed)**: `verify_session_with_timeouts`
//!   denies any session whose JWT role claims (`is_superuser`,
//!   `is_staff`) diverge from the `users` row. Covers EVERY write path,
//!   including ones that forget the event-driven hook (pinned by the
//!   direct-SQL test below).
//! - **Layer B (event-driven)**: `services::session_revocation::
//!   revoke_auth_sessions` deletes the `auth_sessions` rows at each
//!   mutation seam (admin role change, admin password set, self-service
//!   password rotation, CLI password reset) and pushes the WebSocket
//!   force-logout. Required for passwords, which are not claims and
//!   therefore invisible to layer A.
//!
//! Matrix:
//! - role_demotion_revokes_sessions_and_denies_old_cookie
//! - role_promotion_revokes_sessions (one rule, no upgrade special-case)
//! - admin_password_change_revokes_target_sessions
//! - admin_self_password_change_keeps_own_session_revokes_others
//! - self_password_change_keeps_current_session_revokes_others
//! - direct_sql_role_flip_denies_session_next_request (layer A alone)
//! - cli_password_reset_revokes_sessions
//! - privilege_revocation_source_pins (structural drift guards)

use axum::http::header::{COOKIE, LOCATION};
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serial_test::serial;
use uuid::Uuid;
use vauban_web::models::user::AuthSource;
use vauban_web::schema::{auth_sessions, users};
use vauban_web::services::auth::AuthService;

use crate::common::{TestApp, unwrap_ok, unwrap_some};
use crate::fixtures::{create_staff_only_user, create_test_user_with_mfa, unique_name};

// =============================================================================
// Helpers
// =============================================================================

/// Count the live `auth_sessions` rows of a user.
async fn count_sessions(conn: &mut AsyncPgConnection, user_id: i32) -> i64 {
    unwrap_ok!(
        auth_sessions::table
            .filter(auth_sessions::user_id.eq(user_id))
            .count()
            .get_result(conn)
            .await
    )
}

/// Create an active admin (`is_staff + is_superuser`) with an enrolled
/// TOTP factor (required for the password-rotation step-up). Returns
/// `(user_id, uuid, username, mfa_secret)`.
async fn create_admin_with_mfa(app: &TestApp, label: &str) -> (i32, Uuid, String, String) {
    let username = unique_name(label);
    let user_uuid = Uuid::new_v4();
    let hash = unwrap_ok!(app.auth_service.hash_password("StableAdminPwd#2026!"));
    let (mfa_secret, _) = unwrap_ok!(AuthService::generate_totp_secret(&username, "VAUBAN-tests"));

    let mut conn = app.get_conn().await;
    let user_id: i32 = unwrap_ok!(
        diesel::insert_into(users::table)
            .values((
                users::uuid.eq(user_uuid),
                users::username.eq(&username),
                users::email.eq(format!("{}@test.vauban.io", username)),
                users::password_hash.eq(&hash),
                users::is_active.eq(true),
                users::is_staff.eq(true),
                users::is_superuser.eq(true),
                users::mfa_enabled.eq(true),
                users::mfa_secret.eq(Some(&mfa_secret)),
                users::auth_source.eq(AuthSource::Local),
                users::preferences.eq(serde_json::json!({})),
            ))
            .returning(users::id)
            .get_result::<i32>(&mut conn)
            .await
    );
    (user_id, user_uuid, username, mfa_secret)
}

/// Create a plain admin row (no MFA) and return `(user_id, uuid, username)`.
async fn create_admin(app: &TestApp, label: &str) -> (i32, Uuid, String) {
    let username = unique_name(label);
    let user_uuid = Uuid::new_v4();
    let mut conn = app.get_conn().await;
    let user_id: i32 = unwrap_ok!(
        diesel::insert_into(users::table)
            .values((
                users::uuid.eq(user_uuid),
                users::username.eq(&username),
                users::email.eq(format!("{}@test.vauban.io", username)),
                users::password_hash.eq("hash"),
                users::is_active.eq(true),
                users::is_staff.eq(true),
                users::is_superuser.eq(true),
                users::auth_source.eq(AuthSource::Local),
                users::preferences.eq(serde_json::json!({})),
            ))
            .returning(users::id)
            .get_result::<i32>(&mut conn)
            .await
    );
    (user_id, user_uuid, username)
}

/// POST the admin edit form on `target_uuid`. `password` / `totp_code`
/// drive the admin password-set path when provided.
#[allow(clippy::too_many_arguments)]
async fn post_edit(
    app: &TestApp,
    target_uuid: Uuid,
    token: &str,
    csrf: &str,
    username: &str,
    email: &str,
    is_active: bool,
    is_staff: bool,
    is_superuser: bool,
    password: Option<&str>,
    totp_code: Option<&str>,
) -> axum_test::TestResponse {
    let mut form: Vec<(&str, &str)> = vec![
        ("csrf_token", csrf),
        ("username", username),
        ("email", email),
    ];
    if let Some(pwd) = password {
        form.push(("password", pwd));
    }
    if let Some(code) = totp_code {
        form.push(("totp_code", code));
    }
    if is_active {
        form.push(("is_active", "on"));
    }
    if is_staff {
        form.push(("is_staff", "on"));
    }
    if is_superuser {
        form.push(("is_superuser", "on"));
    }
    app.server
        .post(&format!("/accounts/users/{}", target_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf),
        )
        .form(&form)
        .await
}

/// GET an authenticated page with a session cookie and return the status.
async fn get_profile_status(app: &TestApp, token: &str) -> (u16, Option<String>) {
    let response = app
        .server
        .get("/accounts/profile")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    let location = response
        .headers()
        .get(LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    (response.status_code().as_u16(), location)
}

/// Assert a session cookie is DENIED: the web extractor answers with the
/// canonical 303 redirect to `/login`.
async fn assert_denied(app: &TestApp, token: &str, context: &str) {
    let (status, location) = get_profile_status(app, token).await;
    assert_eq!(status, 303, "{context}: expected 303 login redirect");
    assert_eq!(
        location.as_deref(),
        Some("/login"),
        "{context}: expected redirect to /login"
    );
}

// =============================================================================
// Layer B seams (role change / password change / CLI reset)
// =============================================================================

/// Demoting a superuser must delete their `auth_sessions` rows and deny
/// the pre-demotion cookie on the very next request. Re-login is the
/// only way to obtain fresh (downgraded) claims.
#[tokio::test]
#[serial]
async fn role_demotion_revokes_sessions_and_denies_old_cookie() {
    let app = TestApp::spawn().await;

    let (_op_id, op_uuid, op_username) = create_admin(app, "revoke_demote_op").await;
    let (target_id, target_uuid, target_username) = create_admin(app, "revoke_demote_target").await;

    let op_token = app
        .generate_test_token(&op_uuid.to_string(), &op_username, true, true)
        .await;
    let target_token = app
        .generate_test_token(&target_uuid.to_string(), &target_username, true, true)
        .await;

    // Sanity: the target's session works before the demotion.
    let (status, _) = get_profile_status(app, &target_token).await;
    assert_eq!(status, 200, "target session must be valid pre-demotion");

    let csrf = app.generate_csrf_token();
    let email = format!("{}@test.vauban.io", target_username);
    let response = post_edit(
        app,
        target_uuid,
        &op_token,
        &csrf,
        &target_username,
        &email,
        true,
        true,
        false, // demote: superuser -> off
        None,
        None,
    )
    .await;
    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "demotion must succeed with a redirect, got {status}"
    );

    // Layer B: every auth_sessions row of the target is gone.
    let mut conn = app.get_conn().await;
    assert_eq!(
        count_sessions(&mut conn, target_id).await,
        0,
        "role change must delete every login session of the target"
    );
    drop(conn);

    // The old cookie is dead (row deleted -> fail-closed deny).
    assert_denied(app, &target_token, "post-demotion cookie").await;
}

/// Promotion follows the exact same rule as demotion: any role-flag
/// change revokes the target's sessions (no upgrade special-case; the
/// promoted user re-logs to mint claims carrying the new privileges).
#[tokio::test]
#[serial]
async fn role_promotion_revokes_sessions() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let (_op_id, op_uuid, op_username) = create_admin(app, "revoke_promote_op").await;
    let staff = create_staff_only_user(
        &mut conn,
        &app.auth_service,
        &unique_name("revoke_promote_target"),
    )
    .await;
    drop(conn);

    let op_token = app
        .generate_test_token(&op_uuid.to_string(), &op_username, true, true)
        .await;

    // Sanity: the staff session works before the promotion.
    let (status, _) = get_profile_status(app, &staff.token).await;
    assert_eq!(status, 200, "staff session must be valid pre-promotion");

    let csrf = app.generate_csrf_token();
    let response = post_edit(
        app,
        staff.user.uuid,
        &op_token,
        &csrf,
        &staff.user.username,
        &staff.user.email,
        true,
        true,
        true, // promote: superuser -> on
        None,
        None,
    )
    .await;
    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "promotion must succeed with a redirect, got {status}"
    );

    let mut conn = app.get_conn().await;
    assert_eq!(
        count_sessions(&mut conn, staff.user.id).await,
        0,
        "promotion must delete every login session of the target"
    );
    drop(conn);

    assert_denied(app, &staff.token, "post-promotion cookie").await;
}

/// An admin-forced password change must revoke every session of the
/// target: an attacker holding a stolen session must not survive the
/// credential rotation.
#[tokio::test]
async fn admin_password_change_revokes_target_sessions() {
    let app = TestApp::spawn().await;

    let (_op_id, op_uuid, op_username, op_secret) =
        create_admin_with_mfa(app, "revoke_adminpwd_op").await;
    let op_token = app
        .generate_test_token(&op_uuid.to_string(), &op_username, true, true)
        .await;

    // Target: a regular user with one live session (roles unchanged by
    // the edit, so only the password path triggers the revocation).
    let target_username = unique_name("revoke_adminpwd_target");
    let target_uuid = Uuid::new_v4();
    let target_token = app
        .generate_test_token(&target_uuid.to_string(), &target_username, false, false)
        .await;
    let mut conn = app.get_conn().await;
    let target_id: i32 = unwrap_ok!(
        users::table
            .filter(users::uuid.eq(target_uuid))
            .select(users::id)
            .first(&mut conn)
            .await
    );
    assert_eq!(count_sessions(&mut conn, target_id).await, 1);
    drop(conn);

    let (status, _) = get_profile_status(app, &target_token).await;
    assert_eq!(status, 200, "target session must be valid pre-rotation");

    let csrf = app.generate_csrf_token();
    let totp = unwrap_some!(AuthService::get_current_totp(&op_secret));
    let email = format!("{}@test.local", target_username);
    let response = post_edit(
        app,
        target_uuid,
        &op_token,
        &csrf,
        &target_username,
        &email,
        true,
        false,
        false,
        Some("BrandNewPassword#2026!"),
        Some(&totp),
    )
    .await;
    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "admin password set must succeed with a redirect, got {status}"
    );

    let mut conn = app.get_conn().await;
    assert_eq!(
        count_sessions(&mut conn, target_id).await,
        0,
        "admin password change must delete every login session of the target"
    );
    drop(conn);

    assert_denied(app, &target_token, "post-rotation cookie").await;
}

/// When the admin rotates their OWN password through the admin edit
/// form, the session that performed the change survives (no mid-flow
/// logout) while every other session of that admin dies.
#[tokio::test]
async fn admin_self_password_change_keeps_own_session_revokes_others() {
    let app = TestApp::spawn().await;

    let (op_id, op_uuid, op_username, op_secret) =
        create_admin_with_mfa(app, "revoke_selfadmin_op").await;
    let current_token = app
        .generate_test_token(&op_uuid.to_string(), &op_username, true, true)
        .await;
    let other_token = app
        .generate_test_token(&op_uuid.to_string(), &op_username, true, true)
        .await;

    let mut conn = app.get_conn().await;
    assert_eq!(count_sessions(&mut conn, op_id).await, 2);
    drop(conn);

    let csrf = app.generate_csrf_token();
    let totp = unwrap_some!(AuthService::get_current_totp(&op_secret));
    let email = format!("{}@test.vauban.io", op_username);
    let response = post_edit(
        app,
        op_uuid,
        &current_token,
        &csrf,
        &op_username,
        &email,
        true,
        true,
        true, // roles unchanged: self password rotation is allowed
        Some("RotatedByMyself#2026!"),
        Some(&totp),
    )
    .await;
    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "self password set must succeed with a redirect, got {status}"
    );

    let mut conn = app.get_conn().await;
    assert_eq!(
        count_sessions(&mut conn, op_id).await,
        1,
        "exactly the current session must survive a self password change"
    );
    drop(conn);

    let (status, _) = get_profile_status(app, &current_token).await;
    assert_eq!(status, 200, "the operator's own session must survive");
    assert_denied(app, &other_token, "operator's other session").await;
}

/// Self-service rotation (`POST /accounts/profile/password`): the
/// session that performed the rotation survives, every other session of
/// the same user is revoked.
#[tokio::test]
async fn self_password_change_keeps_current_session_revokes_others() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let me =
        create_test_user_with_mfa(&mut conn, &app.auth_service, &unique_name("revoke_selfsvc"))
            .await;
    drop(conn);

    // Second live session for the same user (e.g. another browser).
    let other_token = app
        .generate_test_token(&me.user.uuid.to_string(), &me.user.username, false, false)
        .await;

    let mut conn = app.get_conn().await;
    assert_eq!(count_sessions(&mut conn, me.user.id).await, 2);
    drop(conn);

    let csrf = app.generate_csrf_token();
    let totp = unwrap_some!(AuthService::get_current_totp(&me.mfa_secret));
    let response = app
        .server
        .post("/accounts/profile/password")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", me.token, csrf),
        )
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("new_password", "SelfRotated#2026!"),
            ("confirm_password", "SelfRotated#2026!"),
            ("totp_code", totp.as_str()),
        ])
        .await;
    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "self-service rotation must succeed with a redirect, got {status}"
    );

    let mut conn = app.get_conn().await;
    assert_eq!(
        count_sessions(&mut conn, me.user.id).await,
        1,
        "self-service rotation must keep exactly the current session"
    );
    drop(conn);

    let (status, _) = get_profile_status(app, &me.token).await;
    assert_eq!(status, 200, "the rotating session must survive");
    assert_denied(app, &other_token, "user's other session").await;
}

/// CLI reset (`AdminCommand::ResetPassword` over IPC) must delete every
/// login session of the user: an out-of-band credential rotation (lost
/// password / suspected compromise) leaves no session alive.
#[tokio::test]
async fn cli_password_reset_revokes_sessions() {
    let app = TestApp::spawn().await;

    let username = unique_name("revoke_cli_reset");
    let user_uuid = Uuid::new_v4();
    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;

    let mut conn = app.get_conn().await;
    let user_id: i32 = unwrap_ok!(
        users::table
            .filter(users::uuid.eq(user_uuid))
            .select(users::id)
            .first(&mut conn)
            .await
    );
    assert_eq!(count_sessions(&mut conn, user_id).await, 1);
    drop(conn);

    let response = vauban_web::ipc::admin::handle_admin_command(
        &app.db_pool,
        shared::messages::AdminCommand::ResetPassword {
            username: username.clone(),
            password_hash: "argon2-reset-hash".to_string(),
        },
    )
    .await;
    assert!(
        matches!(response, shared::messages::AdminResponse::Ok),
        "CLI reset must succeed, got {response:?}"
    );

    let mut conn = app.get_conn().await;
    assert_eq!(
        count_sessions(&mut conn, user_id).await,
        0,
        "CLI password reset must delete every login session of the user"
    );
    drop(conn);

    assert_denied(app, &token, "post-CLI-reset cookie").await;
}

// =============================================================================
// Layer A alone (per-request invariant)
// =============================================================================

/// THE key invariant test: flip a role flag directly in SQL -- simulating
/// a write path that forgets the event-driven revocation (future SCIM
/// sync, manual psql, ...). The very next request on the live session
/// must be denied even though the `auth_sessions` row still exists,
/// because `verify_session_with_timeouts` compares the JWT role claims
/// against the DB row on every request.
#[tokio::test]
async fn direct_sql_role_flip_denies_session_next_request() {
    let app = TestApp::spawn().await;

    let username = unique_name("revoke_sql_flip");
    let user_uuid = Uuid::new_v4();
    // Claims minted for a regular user (no staff, no superuser).
    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;

    let (status, _) = get_profile_status(app, &token).await;
    assert_eq!(status, 200, "session must be valid before the SQL flip");

    // Out-of-band privilege change that bypasses every handler.
    let mut conn = app.get_conn().await;
    let user_id: i32 = unwrap_ok!(
        users::table
            .filter(users::uuid.eq(user_uuid))
            .select(users::id)
            .first(&mut conn)
            .await
    );
    unwrap_ok!(
        diesel::update(users::table.filter(users::id.eq(user_id)))
            .set(users::is_staff.eq(true))
            .execute(&mut conn)
            .await
    );
    drop(conn);

    // Layer A: denied on the next request, no event-driven hook involved.
    assert_denied(app, &token, "post-SQL-flip cookie").await;

    // The session row was NOT deleted -- layer A is deny-only. This pins
    // the separation of responsibilities between the two layers.
    let mut conn = app.get_conn().await;
    assert_eq!(
        count_sessions(&mut conn, user_id).await,
        1,
        "layer A must deny without deleting the session row"
    );
}

// =============================================================================
// Structural source pins (drift guards)
// =============================================================================

const MIDDLEWARE_AUTH_SRC: &str = include_str!("../../src/middleware/auth.rs");
const USERS_SRC: &str = include_str!("../../src/handlers/web/users.rs");
const IPC_ADMIN_SRC: &str = include_str!("../../src/ipc/admin.rs");
const SESSION_REVOCATION_SRC: &str = include_str!("../../src/services/session_revocation.rs");

/// Slice the source of one function out of a file (from its `fn name`
/// line to the next top-level `fn`).
fn fn_src<'a>(src: &'a str, needle: &str) -> &'a str {
    let start = src
        .find(needle)
        .unwrap_or_else(|| panic!("`{needle}` must exist"));
    let rest = &src[start + 1..];
    let end = rest
        .find("\nasync fn ")
        .or_else(|| rest.find("\npub async fn "))
        .map(|e| start + 1 + e)
        .unwrap_or(src.len());
    &src[start..end]
}

/// Layer A pin: the session verifier must select and compare BOTH role
/// flags in BOTH lookup branches (jti and token_hash fallback).
#[test]
fn verify_session_compares_role_claims_against_db() {
    let src = fn_src(MIDDLEWARE_AUTH_SRC, "async fn verify_session_with_timeouts");
    assert_eq!(
        src.matches("users::is_superuser, users::is_staff").count(),
        2,
        "both lookup branches must select the role flags from the users join"
    );
    assert!(
        src.contains("claims.is_superuser") && src.contains("claims.is_staff"),
        "the verifier must compare the DB flags against the JWT claims"
    );
}

/// Layer B pin: the admin edit handler must call the shared revocation
/// seam for BOTH triggers (role change, admin password set).
#[test]
fn update_user_web_revokes_on_role_or_password_change() {
    let src = fn_src(USERS_SRC, "pub async fn update_user_web");
    assert!(
        src.contains("role_changed || password_hash.is_some()"),
        "update_user_web must trigger revocation on role change OR password set"
    );
    assert!(
        src.contains("session_revocation::revoke_auth_sessions("),
        "update_user_web must revoke via the shared session_revocation seam"
    );
}

/// Layer B pin: the self-service rotation must revoke the OTHER sessions
/// while keeping the current one.
#[test]
fn change_own_password_revokes_other_sessions_keeps_current() {
    let src = fn_src(USERS_SRC, "pub async fn change_own_password_web");
    assert!(
        src.contains("session_revocation::revoke_auth_sessions("),
        "change_own_password_web must revoke via the shared seam"
    );
    assert!(
        src.contains("Some(session_id.0)"),
        "change_own_password_web must keep the session that performed the rotation"
    );
}

/// Layer B pin: every `password_hash` UPDATE site in the handlers and in
/// the IPC admin tier must be paired with a session revocation in the
/// same function. New write sites fail this test until they wire the
/// revocation in.
#[test]
fn every_password_write_site_revokes_sessions() {
    // users.rs: the two UPDATE sites live in update_user_web (admin set)
    // and change_own_password_web (self rotation); both are pinned above.
    // ipc/admin.rs: the CLI reset must delete the auth_sessions rows.
    let reset_src = fn_src(IPC_ADMIN_SRC, "async fn handle_reset_password");
    assert!(
        reset_src.contains("diesel::delete") && reset_src.contains("auth_sessions"),
        "handle_reset_password must delete the user's auth_sessions rows"
    );

    // Drift guard: no NEW `password_hash.eq(` update site may appear
    // outside the three audited functions.
    for (label, src, expected) in [
        ("users.rs", USERS_SRC, 3), // create (INSERT) + admin set + self rotation
        ("ipc/admin.rs", IPC_ADMIN_SRC, 1),
    ] {
        let count = src.matches("users::password_hash.eq(").count();
        assert_eq!(
            count, expected,
            "{label}: a new `password_hash` write site appeared (found {count}, \
             expected {expected}); wire session revocation in and update this pin"
        );
    }
}

/// The revocation seam itself must fail loudly when the DB is down (the
/// delete is the authoritative act) and must route the force-logout
/// through the canonical helper.
#[test]
fn session_revocation_seam_is_fail_loud_and_single_sourced() {
    assert!(
        SESSION_REVOCATION_SRC.contains("sessions NOT revoked"),
        "revoke_auth_sessions must log an error when the DB pool is unavailable"
    );
    assert!(
        SESSION_REVOCATION_SRC.contains("force_logout_oob("),
        "revoke_auth_sessions must produce the force-logout fragment via the shared helper"
    );
    // SEC-07 stays on the shared seam: deactivate_user must not re-inline
    // its own auth_sessions delete.
    let deact_src = fn_src(USERS_SRC, "pub async fn deactivate_user");
    assert!(
        deact_src.contains("session_revocation::revoke_auth_sessions("),
        "deactivate_user must revoke login sessions via the shared seam"
    );
}
