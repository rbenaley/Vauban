//! End-to-end tests for LDAP/AD login routing at the web layer.
//!
//! These run against [`TestApp::spawn_ldap`], whose `AppState` carries an
//! in-process Auth IPC stub directory (see `common::auth_ipc_test_service`).
//! They focus on the *routing* contract of the login handler:
//!
//!  * existing `Ldap` users authenticate via the directory only (no local
//!    fallback) and never accrue the local lockout counters,
//!  * every directory failure mode collapses to the same generic response as
//!    an unknown user (anti-enumeration, SEC-04/05),
//!  * a successful bind for an unknown username just-in-time provisions a
//!    directory-backed account,
//!  * MFA is always enforced on top of the bind,
//!  * local accounts keep working regardless of the directory.
//!
//! The genuine TLS + FD-passing + BER simple-bind path is covered separately by
//! `vauban-auth/tests/ldap_bind_e2e_test.rs`.

use axum::http::{HeaderName, header};
use serde_json::json;
use serial_test::serial;

use diesel::{ExpressionMethods, OptionalExtension, QueryDsl};
use diesel_async::AsyncPgConnection;
use diesel_async::RunQueryDsl as _;

use crate::common::auth_ipc_test_service::{
    LDAP_DOWN_USERNAME, LDAP_GOOD_PASSWORD, StubSearchMode, ldap_bind_attempt_count,
    reset_ldap_bind_attempt_count, reset_stub_search, set_stub_search,
};
use crate::common::{
    TEST_ADMINS_DIRECTORY_KEY, TestApp, test_aggregation_group_key, test_db, unwrap_ok,
};
use crate::fixtures::unique_name;
use shared::messages::VaubanGroupInfo;
use vauban_web::models::user::{AuthSource, NewUser, User};
use vauban_web::schema::{auth_sessions, users};

/// A wrong directory password that still satisfies the request validator
/// (>= 12 chars) so the bind path is actually exercised.
const LDAP_WRONG_PASSWORD: &str = "Wrong-Dir-Pass-9!";

async fn insert_ldap_user(conn: &mut AsyncPgConnection, username: &str, mfa_enabled: bool) -> User {
    let new_user = NewUser {
        uuid: ::uuid::Uuid::new_v4(),
        username: username.to_string(),
        email: format!("{}@ldap.local", username),
        password_hash: "!ldap-no-local-login".to_string(),
        first_name: None,
        last_name: None,
        phone: None,
        is_active: true,
        is_staff: false,
        is_superuser: false,
        is_service_account: false,
        mfa_enabled,
        mfa_enforced: false,
        mfa_secret: None,
        preferences: serde_json::json!({}),
        auth_source: AuthSource::Ldap,
        external_id: Some(username.to_string()),
    };
    unwrap_ok!(
        diesel::insert_into(users::table)
            .values(&new_user)
            .get_result(conn)
            .await
    )
}

async fn reload_user(conn: &mut AsyncPgConnection, username: &str) -> Option<User> {
    users::table
        .filter(users::username.eq(username))
        .filter(users::is_deleted.eq(false))
        .first::<User>(conn)
        .await
        .optional()
        .unwrap_or(None)
}

async fn session_count(conn: &mut AsyncPgConnection, user_id: i32) -> i64 {
    auth_sessions::table
        .filter(auth_sessions::user_id.eq(user_id))
        .count()
        .get_result(conn)
        .await
        .unwrap_or(0)
}

/// POST the HTMX web-login form (CSRF-protected) and return the response.
async fn login_web_htmx(app: &TestApp, username: &str, password: &str) -> axum_test::TestResponse {
    let csrf = app.generate_csrf_token();
    app.server
        .post("/auth/login")
        .add_header(header::COOKIE, format!("__vauban_csrf={}", csrf))
        .add_header(HeaderName::from_static("hx-request"), "true")
        .json(&json!({
            "username": username,
            "password": password,
            "csrf_token": csrf,
        }))
        .await
}

fn hx_redirect(response: &axum_test::TestResponse) -> Option<String> {
    response
        .headers()
        .get("HX-Redirect")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// Existing `Ldap` user + correct directory password -> authenticated, routed
/// to MFA enrolment, and a (temporary) session row is created.
#[tokio::test]
#[serial]
async fn ldap_user_valid_password_creates_session_and_requires_mfa() {
    let app = TestApp::spawn_ldap().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("test_ldap_ok");
    let user = insert_ldap_user(&mut conn, &username, false).await;

    let response = login_web_htmx(app, &username, LDAP_GOOD_PASSWORD).await;

    assert_eq!(response.status_code().as_u16(), 200);
    assert_eq!(hx_redirect(&response).as_deref(), Some("/mfa/setup"));
    assert!(
        session_count(&mut conn, user.id).await >= 1,
        "a session must be created on successful LDAP login"
    );

    test_db::cleanup(&mut conn).await;
}

/// Existing `Ldap` user with MFA already enabled -> routed to MFA verification.
#[tokio::test]
#[serial]
async fn ldap_user_with_mfa_routes_to_verify() {
    let app = TestApp::spawn_ldap().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("test_ldap_mfa");
    insert_ldap_user(&mut conn, &username, true).await;

    let response = login_web_htmx(app, &username, LDAP_GOOD_PASSWORD).await;

    assert_eq!(response.status_code().as_u16(), 200);
    assert_eq!(hx_redirect(&response).as_deref(), Some("/mfa/verify"));

    test_db::cleanup(&mut conn).await;
}

/// Wrong directory password for an existing `Ldap` user must be
/// indistinguishable from an unknown user (anti-enumeration) AND must NOT
/// increment the local lockout counters (the directory owns its lockout).
#[tokio::test]
#[serial]
async fn ldap_user_wrong_password_is_generic_and_skips_lockout() {
    let app = TestApp::spawn_ldap().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("test_ldap_bad");
    insert_ldap_user(&mut conn, &username, false).await;

    let response = login_web_htmx(app, &username, LDAP_WRONG_PASSWORD).await;
    assert_eq!(response.status_code().as_u16(), 200);
    assert!(
        hx_redirect(&response).is_none(),
        "must not redirect on failure"
    );
    let ldap_body = response.text();

    // Same request shape for a username that does not exist at all.
    let unknown = unique_name("test_ldap_ghost");
    let unknown_response = login_web_htmx(app, &unknown, LDAP_WRONG_PASSWORD).await;
    let unknown_body = unknown_response.text();

    assert_eq!(
        ldap_body, unknown_body,
        "wrong-password and unknown-user responses must be byte-identical"
    );

    // Lockout counters must be untouched for the directory-backed account.
    let reloaded = reload_user(&mut conn, &username)
        .await
        .expect("ldap user still exists");
    assert_eq!(
        reloaded.failed_login_attempts, 0,
        "LDAP failures must not increment failed_login_attempts"
    );
    assert!(
        reloaded.locked_until.is_none(),
        "LDAP failures must not set locked_until"
    );

    test_db::cleanup(&mut conn).await;
}

/// Unknown username + successful directory bind -> JIT provisioning of a new
/// `Ldap` account, then routed to MFA enrolment.
#[tokio::test]
#[serial]
async fn unknown_user_valid_bind_jit_provisions_ldap_account() {
    let app = TestApp::spawn_ldap().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("test_ldap_jit");
    assert!(
        reload_user(&mut conn, &username).await.is_none(),
        "precondition: user must not exist yet"
    );

    let response = login_web_htmx(app, &username, LDAP_GOOD_PASSWORD).await;

    assert_eq!(response.status_code().as_u16(), 200);
    assert_eq!(hx_redirect(&response).as_deref(), Some("/mfa/setup"));

    let provisioned = reload_user(&mut conn, &username)
        .await
        .expect("JIT user must be provisioned");
    assert_eq!(provisioned.auth_source, AuthSource::Ldap);
    assert_eq!(provisioned.external_id.as_deref(), Some(username.as_str()));
    assert!(provisioned.is_active);

    test_db::cleanup(&mut conn).await;
}

/// Directory unreachable for an unknown username -> generic failure, fail-closed
/// (no account is provisioned, no panic).
#[tokio::test]
#[serial]
async fn unknown_user_directory_down_fails_closed() {
    let app = TestApp::spawn_ldap().await;
    let mut conn = app.get_conn().await;

    // LDAP_DOWN_USERNAME makes the stub directory report `Unreachable`.
    let response = login_web_htmx(app, LDAP_DOWN_USERNAME, LDAP_GOOD_PASSWORD).await;

    assert_eq!(response.status_code().as_u16(), 200);
    assert!(
        hx_redirect(&response).is_none(),
        "an unreachable directory must not authenticate the user"
    );
    assert!(
        reload_user(&mut conn, LDAP_DOWN_USERNAME).await.is_none(),
        "no account may be provisioned when the directory is unreachable"
    );

    test_db::cleanup(&mut conn).await;
}

/// Local accounts authenticate normally even with LDAP enabled (break-glass):
/// the local Argon2 path is independent of the directory's availability.
#[tokio::test]
#[serial]
async fn local_account_authenticates_with_ldap_enabled() {
    let app = TestApp::spawn_ldap().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("test_local_bg");
    let password = "LocalBreakGlass-1!";
    let password_hash = unwrap_ok!(app.auth_service.hash_password(password));

    let new_user = NewUser {
        uuid: ::uuid::Uuid::new_v4(),
        username: username.clone(),
        email: format!("{}@test.vauban.io", username),
        password_hash,
        first_name: None,
        last_name: None,
        phone: None,
        is_active: true,
        is_staff: false,
        is_superuser: false,
        is_service_account: false,
        mfa_enabled: false,
        mfa_enforced: false,
        mfa_secret: None,
        preferences: serde_json::json!({}),
        auth_source: AuthSource::Local,
        external_id: None,
    };
    let _user: User = unwrap_ok!(
        diesel::insert_into(users::table)
            .values(&new_user)
            .get_result(&mut conn)
            .await
    );

    // Correct local password -> authenticated (routed to MFA enrolment).
    let response = login_web_htmx(app, &username, password).await;
    assert_eq!(response.status_code().as_u16(), 200);
    assert_eq!(hx_redirect(&response).as_deref(), Some("/mfa/setup"));

    // A local account must NEVER be routed through the directory: the canonical
    // LDAP password must not authenticate it.
    let response_ldap_pw = login_web_htmx(app, &username, LDAP_GOOD_PASSWORD).await;
    assert!(
        hx_redirect(&response_ldap_pw).is_none(),
        "local accounts must not accept the directory password"
    );

    test_db::cleanup(&mut conn).await;
}

/// Password shorter than the absolute floor (12) must never reach AuthLdapBind.
#[tokio::test]
#[serial]
async fn short_password_never_sends_auth_ldap_bind() {
    let app = TestApp::spawn_ldap().await;
    reset_ldap_bind_attempt_count();
    let before = ldap_bind_attempt_count();

    let username = unique_name("test_ldap_short");
    let response = login_web_htmx(app, &username, "short-pass").await; // 10 chars

    assert_eq!(response.status_code().as_u16(), 200);
    assert!(
        hx_redirect(&response).is_none(),
        "below-mins login must not authenticate"
    );
    assert_eq!(
        ldap_bind_attempt_count(),
        before,
        "AuthLdapBind must not be sent when password is below login_password_min_length"
    );
    assert!(
        response.text().contains("Incorrect") || response.text().contains("incorrect"),
        "client must see the generic invalid-credentials message"
    );
}

/// Username shorter than the absolute floor (3) must never reach AuthLdapBind.
#[tokio::test]
#[serial]
async fn short_username_never_sends_auth_ldap_bind() {
    let app = TestApp::spawn_ldap().await;
    reset_ldap_bind_attempt_count();
    let before = ldap_bind_attempt_count();

    let response = login_web_htmx(app, "ab", LDAP_GOOD_PASSWORD).await;

    assert_eq!(response.status_code().as_u16(), 200);
    assert!(hx_redirect(&response).is_none());
    assert_eq!(
        ldap_bind_attempt_count(),
        before,
        "AuthLdapBind must not be sent when username is below login_username_min_length"
    );
}

/// Even an existing directory-backed account never hits the stub when the
/// typed password is below the login-form floor (gate is before auth_source).
#[tokio::test]
#[serial]
async fn existing_ldap_user_short_password_never_binds() {
    let app = TestApp::spawn_ldap().await;
    let mut conn = app.get_conn().await;
    reset_ldap_bind_attempt_count();
    let before = ldap_bind_attempt_count();

    let username = unique_name("test_ldap_exist_short");
    insert_ldap_user(&mut conn, &username, false).await;

    let response = login_web_htmx(app, &username, "tooshort").await; // 8 chars
    assert_eq!(response.status_code().as_u16(), 200);
    assert!(hx_redirect(&response).is_none());
    assert_eq!(
        ldap_bind_attempt_count(),
        before,
        "existing Ldap users must still be blocked by login-form floors before bind"
    );

    test_db::cleanup(&mut conn).await;
}

/// Raised `[auth.ldaps].login_password_min_length` (20): a 15-char password
/// (above absolute floor 12) still must not contact the directory.
#[tokio::test]
#[serial]
async fn raised_password_min_skips_bind_for_mid_length_password() {
    let app = TestApp::spawn_ldap_raised_password_min().await;
    reset_ldap_bind_attempt_count();
    let before = ldap_bind_attempt_count();

    let username = unique_name("test_ldap_mid");
    // 15 chars: passes absolute floor 12, fails configured min 20.
    let response = login_web_htmx(app, &username, "123456789012345").await;

    assert_eq!(response.status_code().as_u16(), 200);
    assert!(hx_redirect(&response).is_none());
    assert_eq!(
        ldap_bind_attempt_count(),
        before,
        "AuthLdapBind must not be sent when password is below raised login_password_min_length"
    );
}

/// Control: a password that meets the floors still reaches the stub (counter bumps).
#[tokio::test]
#[serial]
async fn password_meeting_floors_still_reaches_ldap_stub() {
    let app = TestApp::spawn_ldap().await;
    let mut conn = app.get_conn().await;
    reset_ldap_bind_attempt_count();
    let before = ldap_bind_attempt_count();

    let username = unique_name("test_ldap_reach");
    insert_ldap_user(&mut conn, &username, false).await;

    let response = login_web_htmx(app, &username, LDAP_WRONG_PASSWORD).await;
    assert!(hx_redirect(&response).is_none());
    assert!(
        ldap_bind_attempt_count() > before,
        "AuthLdapBind must be attempted when credentials meet login mins"
    );

    test_db::cleanup(&mut conn).await;
}

// ---------------------------------------------------------------------------
// Phase 1 aggregation (replace-set / A-B-C / local isolation)
// ---------------------------------------------------------------------------

async fn ensure_group(app: &TestApp, name: &str) -> VaubanGroupInfo {
    let groups = unwrap_ok!(app.app_state.access_client.list_vauban_groups().await);
    if let Some(g) = groups
        .into_iter()
        .find(|g| g.name.eq_ignore_ascii_case(name))
    {
        return g;
    }
    unwrap_ok!(
        app.app_state
            .access_client
            .create_vauban_group(name, None)
            .await
    )
}

async fn user_group_names(app: &TestApp, user_id: i32) -> Vec<String> {
    let groups = unwrap_ok!(app.app_state.access_client.list_user_groups(user_id).await);
    let mut names: Vec<String> = groups.into_iter().map(|g| g.name).collect();
    names.sort();
    names
}

fn incomplete_streak(app: &TestApp) -> u32 {
    let rt = app.app_state.ldap_mapping.as_ref().expect("runtime");
    std::sync::atomic::AtomicU32::load(&rt.incomplete_streak, std::sync::atomic::Ordering::SeqCst)
}

fn reset_aggregation(app: &TestApp) {
    reset_stub_search();
    if let Some(rt) = app.app_state.ldap_mapping.as_ref() {
        rt.reset_counters();
    }
}

/// Case A: mapped directory key becomes a `user_groups` row via access IPC.
#[tokio::test]
#[serial]
async fn aggregation_replace_set_adds_mapped_group() {
    let app = TestApp::spawn_ldap_aggregation().await;
    reset_aggregation(app);
    let mut conn = app.get_conn().await;

    let username = unique_name("test_ldap_agg_a");
    let group_name = unique_name("ops");
    let group = ensure_group(app, &group_name).await;
    let user = insert_ldap_user(&mut conn, &username, false).await;

    set_stub_search(
        StubSearchMode::Complete,
        vec![test_aggregation_group_key(&group_name)],
    );
    let response = login_web_htmx(app, &username, LDAP_GOOD_PASSWORD).await;
    assert_eq!(hx_redirect(&response).as_deref(), Some("/mfa/setup"));

    let names = user_group_names(app, user.id).await;
    assert!(
        names.iter().any(|n| n == &group_name),
        "expected {group_name} in {names:?}"
    );
    assert_eq!(group.name, group_name);

    reset_aggregation(app);
    test_db::cleanup(&mut conn).await;
}

/// `static` reserved target: only the static key grants Administrators.
#[tokio::test]
#[serial]
async fn aggregation_reserved_target_only_via_static_key() {
    let app = TestApp::spawn_ldap_aggregation().await;
    reset_aggregation(app);
    let mut conn = app.get_conn().await;

    let admins = ensure_group(app, "Administrators").await;
    let username = unique_name("test_ldap_agg_res");
    let user = insert_ldap_user(&mut conn, &username, false).await;

    set_stub_search(
        StubSearchMode::Complete,
        vec![test_aggregation_group_key("Administrators")],
    );
    let _ = login_web_htmx(app, &username, LDAP_GOOD_PASSWORD).await;
    assert!(
        !user_group_names(app, user.id)
            .await
            .iter()
            .any(|n| n.eq_ignore_ascii_case("Administrators")),
        "match must not grant the reserved static target"
    );

    set_stub_search(
        StubSearchMode::Complete,
        vec![TEST_ADMINS_DIRECTORY_KEY.to_string()],
    );
    let _ = login_web_htmx(app, &username, LDAP_GOOD_PASSWORD).await;
    assert!(
        user_group_names(app, user.id)
            .await
            .iter()
            .any(|n| n.eq_ignore_ascii_case("Administrators")),
        "static key must grant Administrators"
    );
    let _ = admins.id;

    reset_aggregation(app);
    test_db::cleanup(&mut conn).await;
}

/// Local accounts never receive LDAP replace-set memberships.
#[tokio::test]
#[serial]
async fn aggregation_does_not_touch_local_account_groups() {
    let app = TestApp::spawn_ldap_aggregation().await;
    reset_aggregation(app);
    let mut conn = app.get_conn().await;

    let group_name = unique_name("localhold");
    let mapped = unique_name("mapped");
    let hold = ensure_group(app, &group_name).await;
    let _mapped = ensure_group(app, &mapped).await;

    let username = unique_name("test_local_iso");
    let password = "LocalBreakGlass-1!";
    let password_hash = unwrap_ok!(app.auth_service.hash_password(password));
    let new_user = NewUser {
        uuid: ::uuid::Uuid::new_v4(),
        username: username.clone(),
        email: format!("{}@test.vauban.io", username),
        password_hash,
        first_name: None,
        last_name: None,
        phone: None,
        is_active: true,
        is_staff: false,
        is_superuser: false,
        is_service_account: false,
        mfa_enabled: false,
        mfa_enforced: false,
        mfa_secret: None,
        preferences: serde_json::json!({}),
        auth_source: AuthSource::Local,
        external_id: None,
    };
    let user: User = unwrap_ok!(
        diesel::insert_into(users::table)
            .values(&new_user)
            .get_result(&mut conn)
            .await
    );
    unwrap_ok!(
        app.app_state
            .access_client
            .add_group_member(hold.id, user.id)
            .await
    );

    reset_ldap_bind_attempt_count();
    let before = ldap_bind_attempt_count();
    set_stub_search(
        StubSearchMode::Complete,
        vec![test_aggregation_group_key(&mapped)],
    );
    let response = login_web_htmx(app, &username, password).await;
    assert_eq!(hx_redirect(&response).as_deref(), Some("/mfa/setup"));
    assert_eq!(
        ldap_bind_attempt_count(),
        before,
        "local login must not send LDAP bind or bind-and-search"
    );
    assert_eq!(user_group_names(app, user.id).await, vec![group_name]);

    reset_aggregation(app);
    test_db::cleanup(&mut conn).await;
}

/// Case B: search not-found holds memberships and does not deactivate.
#[tokio::test]
#[serial]
async fn search_entry_not_found_does_not_deactivate() {
    let app = TestApp::spawn_ldap_aggregation().await;
    reset_aggregation(app);
    let mut conn = app.get_conn().await;

    let username = unique_name("test_ldap_agg_b");
    let group_name = unique_name("holdb");
    let group = ensure_group(app, &group_name).await;
    let user = insert_ldap_user(&mut conn, &username, false).await;
    unwrap_ok!(
        app.app_state
            .access_client
            .add_group_member(group.id, user.id)
            .await
    );

    set_stub_search(StubSearchMode::IncompleteNotFound, Vec::new());
    let response = login_web_htmx(app, &username, LDAP_GOOD_PASSWORD).await;
    assert_eq!(hx_redirect(&response).as_deref(), Some("/mfa/setup"));

    let reloaded = reload_user(&mut conn, &username)
        .await
        .expect("user remains");
    assert!(reloaded.is_active, "case B must not deactivate");
    assert!(!reloaded.is_staff);
    assert!(!reloaded.is_superuser);
    assert_eq!(user_group_names(app, user.id).await, vec![group_name]);
    assert_eq!(incomplete_streak(app), 1);

    reset_aggregation(app);
    test_db::cleanup(&mut conn).await;
}

/// Case C at threshold: purge groups, keep the account active; case A restores.
#[tokio::test]
#[serial]
async fn aggregation_purge_c_does_not_deactivate_then_restores() {
    let app = TestApp::spawn_ldap_aggregation().await;
    reset_aggregation(app);
    let mut conn = app.get_conn().await;

    let username = unique_name("test_ldap_agg_c");
    let group_name = unique_name("holdc");
    let group = ensure_group(app, &group_name).await;
    let user = insert_ldap_user(&mut conn, &username, false).await;
    unwrap_ok!(
        app.app_state
            .access_client
            .add_group_member(group.id, user.id)
            .await
    );

    set_stub_search(StubSearchMode::IncompleteUnreachable, Vec::new());
    for _ in 0..3 {
        let response = login_web_htmx(app, &username, LDAP_GOOD_PASSWORD).await;
        assert_eq!(hx_redirect(&response).as_deref(), Some("/mfa/setup"));
    }

    let reloaded = reload_user(&mut conn, &username)
        .await
        .expect("user remains");
    assert!(reloaded.is_active, "purge must not deactivate");
    assert!(user_group_names(app, user.id).await.is_empty());

    set_stub_search(
        StubSearchMode::Complete,
        vec![test_aggregation_group_key(&group_name)],
    );
    let response = login_web_htmx(app, &username, LDAP_GOOD_PASSWORD).await;
    assert_eq!(hx_redirect(&response).as_deref(), Some("/mfa/setup"));
    assert!(
        user_group_names(app, user.id)
            .await
            .iter()
            .any(|n| n == &group_name),
        "case A must restore membership after purge"
    );
    assert_eq!(incomplete_streak(app), 0);

    reset_aggregation(app);
    test_db::cleanup(&mut conn).await;
}

/// Bind failure (wrong password) must not increment the aggregation streak.
#[tokio::test]
#[serial]
async fn bind_failure_does_not_increment_aggregation_streak() {
    let app = TestApp::spawn_ldap_aggregation().await;
    reset_aggregation(app);
    let mut conn = app.get_conn().await;

    let username = unique_name("test_ldap_agg_bindfail");
    insert_ldap_user(&mut conn, &username, false).await;
    set_stub_search(StubSearchMode::IncompleteUnreachable, Vec::new());

    let response = login_web_htmx(app, &username, LDAP_WRONG_PASSWORD).await;
    assert!(hx_redirect(&response).is_none());
    assert_eq!(incomplete_streak(app), 0);

    reset_aggregation(app);
    test_db::cleanup(&mut conn).await;
}

/// JIT first login runs aggregation immediately (no `user_groups` from JIT).
#[tokio::test]
#[serial]
async fn jit_first_login_applies_aggregation() {
    let app = TestApp::spawn_ldap_aggregation().await;
    reset_aggregation(app);
    let mut conn = app.get_conn().await;

    let username = unique_name("test_ldap_agg_jit");
    let group_name = unique_name("jitops");
    ensure_group(app, &group_name).await;
    set_stub_search(
        StubSearchMode::Complete,
        vec![test_aggregation_group_key(&group_name)],
    );

    let response = login_web_htmx(app, &username, LDAP_GOOD_PASSWORD).await;
    assert_eq!(hx_redirect(&response).as_deref(), Some("/mfa/setup"));
    let provisioned = reload_user(&mut conn, &username).await.expect("JIT user");
    assert_eq!(provisioned.auth_source, AuthSource::Ldap);
    assert!(
        user_group_names(app, provisioned.id)
            .await
            .iter()
            .any(|n| n == &group_name)
    );

    reset_aggregation(app);
    test_db::cleanup(&mut conn).await;
}
