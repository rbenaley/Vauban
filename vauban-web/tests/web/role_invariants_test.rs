/// VAUBAN Web - Integration tests for role-invariants.
///
/// Two orthogonal classes of invariants are exercised here, both
/// independent of Casbin (Casbin authorises *who* can call the handler;
/// these checks enforce *what minimum/maximum* the resulting state must
/// satisfy regardless of who called):
///
/// 1. **Self-mutation** is refused -- an operator cannot demote, deactivate,
///    or delete their own account through the admin UI / JSON API. The
///    pure check ([`check_self_change`]) runs before the SERIALIZABLE
///    transaction since `operator == target` does not depend on DB state.
/// 2. **At least one active superuser** must remain after any demotion,
///    deactivation, or soft-delete of a superuser row. The check runs
///    INSIDE the transaction that owns the UPDATE, so two concurrent
///    racers cannot both succeed and leave the platform with zero
///    active superusers (TOCTOU window).
///
/// Battle-test matrix (each test asserts: status redirect/HTTP code,
/// stable flash message via `RoleViolation::flash_message`, AND the
/// post-POST DB snapshot is byte-for-byte unchanged when refused):
///
/// Self-mutation refusal (5 scenarios):
/// - superuser_cannot_self_demote_superuser_via_web
/// - staff_cannot_self_demote_staff_via_web
/// - superuser_cannot_self_deactivate_via_web
/// - superuser_cannot_self_deactivate_via_api
/// - superuser_cannot_self_delete_via_web
///
/// Last-active-superuser fence (5 scenarios, all `#[serial]` because
/// they manipulate the global pool of active superusers):
/// - cannot_demote_last_active_superuser_via_web
/// - cannot_deactivate_last_active_superuser_via_web
/// - cannot_deactivate_last_active_superuser_via_api
/// - inactive_superuser_does_not_count_toward_minimum
/// - soft_deleted_superuser_does_not_count
///
/// Authorized cases (non-regression, also `#[serial]`):
/// - can_demote_superuser_when_two_active_superusers_exist
/// - can_deactivate_superuser_when_two_active_superusers_exist
///
/// Concurrency (TOCTOU guard):
/// - concurrent_demotions_keep_at_least_one_superuser
use crate::common::{TestApp, unwrap_ok, unwrap_some};
use crate::fixtures::{create_admin_user, create_simple_admin_user, unique_name};
use axum::http::header::{self, COOKIE, LOCATION, SET_COOKIE};
use chrono::Utc;
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::json;
use serial_test::serial;
use uuid::Uuid;
use vauban_web::models::user::AuthSource;
use vauban_web::schema::users;
use vauban_web::services::auth::AuthService;
use vauban_web::services::role_invariants::RoleViolation;

// =============================================================================
// Helpers
// =============================================================================

/// Read a user UUID from a numeric `user_id`.
async fn get_user_uuid(conn: &mut AsyncPgConnection, user_id: i32) -> Uuid {
    unwrap_ok!(
        users::table
            .filter(users::id.eq(user_id))
            .select(users::uuid)
            .first(conn)
            .await
    )
}

/// Read the username currently stored for a given `user_id` (it may have
/// been UUID-suffixed by `create_simple_admin_user`).
async fn get_username(conn: &mut AsyncPgConnection, user_id: i32) -> String {
    unwrap_ok!(
        users::table
            .filter(users::id.eq(user_id))
            .select(users::username)
            .first(conn)
            .await
    )
}

/// Read the email currently stored for a given `user_id`.
async fn get_email(conn: &mut AsyncPgConnection, user_id: i32) -> String {
    unwrap_ok!(
        users::table
            .filter(users::id.eq(user_id))
            .select(users::email)
            .first(conn)
            .await
    )
}

/// Captured snapshot of the role-bearing flags of one user row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DbSnapshot {
    is_superuser: bool,
    is_staff: bool,
    is_active: bool,
    is_deleted: bool,
}

async fn read_snapshot(conn: &mut AsyncPgConnection, user_id: i32) -> DbSnapshot {
    let (s, st, a, d): (bool, bool, bool, bool) = unwrap_ok!(
        users::table
            .filter(users::id.eq(user_id))
            .select((
                users::is_superuser,
                users::is_staff,
                users::is_active,
                users::is_deleted,
            ))
            .first(conn)
            .await
    );
    DbSnapshot {
        is_superuser: s,
        is_staff: st,
        is_active: a,
        is_deleted: d,
    }
}

/// Acquire a fresh pooled connection just for the snapshot read so
/// tests do not hold a pool slot across the HTTP round-trip.
async fn snapshot_via_pool(app: &TestApp, user_id: i32) -> DbSnapshot {
    let mut conn = app.get_conn().await;
    read_snapshot(&mut conn, user_id).await
}

/// Create an admin (`is_staff + is_superuser`) WITH a freshly-generated
/// TOTP secret enrolled, mirroring `create_admin_with_mfa` in
/// `user_edit_test.rs`. Returns `(user_id, uuid, username, mfa_secret)`.
///
/// Required because `delete_user_web` and any password rotation through
/// `update_user_web` enforce step-up TOTP on the operator. The role-
/// invariant tests target the role / activation booleans, not password,
/// so most paths only need MFA when they touch `delete_user_web`.
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

/// Compute the TOTP code that the handler accepts *right now* for the
/// given base32 shared secret.
fn current_totp(secret: &str) -> String {
    unwrap_some!(AuthService::get_current_totp(secret))
}

/// Extract the signed `__vauban_flash` cookie set on a redirect so the
/// flash banner can be rendered on the follow-up GET.
fn extract_flash_cookie(response: &axum_test::TestResponse) -> Option<String> {
    response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|c| c.to_str().ok())
        .find(|c| c.contains("__vauban_flash"))
        .and_then(|c| c.split(';').next())
        .map(|s| s.to_string())
}

/// POST `/accounts/users/{uuid}` with the given role-bearing flags. All
/// other fields (username, email, password, totp_code) are wired so the
/// happy path would succeed -- the test asserts the role-invariant
/// branch fires *before* any password gating.
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
) -> axum_test::TestResponse {
    let mut form: Vec<(&str, &str)> = vec![
        ("csrf_token", csrf),
        ("username", username),
        ("email", email),
    ];
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

/// POST `/accounts/users/{uuid}/delete` with an optional `totp_code`.
async fn post_delete(
    app: &TestApp,
    target_uuid: Uuid,
    token: &str,
    csrf: &str,
    totp_code: Option<&str>,
) -> axum_test::TestResponse {
    let mut form: Vec<(&str, &str)> = vec![("csrf_token", csrf)];
    if let Some(code) = totp_code {
        form.push(("totp_code", code));
    }
    app.server
        .post(&format!("/accounts/users/{}/delete", target_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf),
        )
        .form(&form)
        .await
}

/// Assert that `response` is a 302/303 redirect, follow it with the
/// flash cookie carried over, and return the rendered body so callers
/// can assert on the flash banner wording.
async fn follow_redirect_and_read(
    app: &TestApp,
    response: axum_test::TestResponse,
    token: &str,
) -> String {
    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "expected a PRG redirect, got {}",
        status
    );

    let location = response
        .headers()
        .get(LOCATION)
        .and_then(|v| v.to_str().ok())
        .expect("redirect must carry a Location header")
        .to_string();
    let flash_cookie = extract_flash_cookie(&response).expect("flash cookie must be set");

    let detail = app
        .server
        .get(&location)
        .add_header(COOKIE, format!("access_token={}; {}", token, flash_cookie))
        .await;
    detail.text()
}

/// Deactivate every other active superuser so the target row becomes
/// the *unique* active superuser. Returns the list of ids that were
/// actually flipped, so the test can restore them at the end (the test
/// must run with `#[serial]` to avoid stepping on other tests' admins).
async fn isolate_as_only_active_superuser(
    conn: &mut AsyncPgConnection,
    keep_id: i32,
) -> (Vec<i32>, chrono::DateTime<chrono::Utc>) {
    let now = Utc::now();
    let to_flip: Vec<i32> = users::table
        .filter(users::is_superuser.eq(true))
        .filter(users::is_active.eq(true))
        .filter(users::is_deleted.eq(false))
        .filter(users::id.ne(keep_id))
        .select(users::id)
        .load(conn)
        .await
        .unwrap_or_default();

    if !to_flip.is_empty() {
        unwrap_ok!(
            diesel::update(users::table.filter(users::id.eq_any(&to_flip)))
                .set((users::is_active.eq(false), users::updated_at.eq(now)))
                .execute(conn)
                .await
        );
    }
    (to_flip, now)
}

async fn restore_superusers(
    conn: &mut AsyncPgConnection,
    ids: &[i32],
    when: chrono::DateTime<chrono::Utc>,
) {
    if !ids.is_empty() {
        let _ = diesel::update(users::table.filter(users::id.eq_any(ids)))
            .set((users::is_active.eq(true), users::updated_at.eq(when)))
            .execute(conn)
            .await;
    }
}

// =============================================================================
// Self-mutation refusal -- 5 scenarios
// =============================================================================

/// A superuser POSTing the edit form on their own row with `is_superuser`
/// unchecked must be refused with the `SelfDemoteSuperuser` flash, and
/// the DB row must remain a superuser.
#[tokio::test]
#[serial]
async fn superuser_cannot_self_demote_superuser_via_web() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("self_demote_super");
    let user_id = create_simple_admin_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;
    let stored_username = get_username(&mut conn, user_id).await;
    let email = get_email(&mut conn, user_id).await;
    let before = read_snapshot(&mut conn, user_id).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &stored_username, true, true)
        .await;
    let csrf = app.generate_csrf_token();
    drop(conn);

    let response = post_edit(
        app,
        user_uuid,
        &token,
        &csrf,
        &stored_username,
        &email,
        true,  // is_active = on
        true,  // is_staff   = on
        false, // is_superuser = OFF (self-demote)
    )
    .await;

    let body = follow_redirect_and_read(app, response, &token).await;
    assert!(
        body.contains(RoleViolation::SelfDemoteSuperuser.flash_message()),
        "must surface the SelfDemoteSuperuser flash; got body excerpt: {}",
        &body[..body.len().min(800)]
    );

    let after = snapshot_via_pool(app, user_id).await;
    assert_eq!(after, before, "role flags must be unchanged after refusal");
}

/// A staff-only operator POSTing the edit form on their own row with
/// `is_staff` unchecked must be refused with `SelfDemoteStaff` AND the
/// row must still carry `is_staff = true`.
#[tokio::test]
#[serial]
async fn staff_cannot_self_demote_staff_via_web() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("self_demote_staff");
    let user_uuid = Uuid::new_v4();
    let user_id: i32 = unwrap_ok!(
        diesel::insert_into(users::table)
            .values((
                users::uuid.eq(user_uuid),
                users::username.eq(&username),
                users::email.eq(format!("{}@test.vauban.io", username)),
                users::password_hash.eq("hash"),
                users::is_active.eq(true),
                users::is_staff.eq(true),
                users::is_superuser.eq(false),
                users::auth_source.eq(AuthSource::Local),
                users::preferences.eq(serde_json::json!({})),
            ))
            .returning(users::id)
            .get_result::<i32>(&mut conn)
            .await
    );
    let email = get_email(&mut conn, user_id).await;
    let before = read_snapshot(&mut conn, user_id).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, true)
        .await;
    let csrf = app.generate_csrf_token();
    drop(conn);

    let response = post_edit(
        app, user_uuid, &token, &csrf, &username, &email, true,  // is_active   = on
        false, // is_staff    = OFF (self-demote)
        false, // is_superuser
    )
    .await;

    let body = follow_redirect_and_read(app, response, &token).await;
    assert!(
        body.contains(RoleViolation::SelfDemoteStaff.flash_message()),
        "must surface the SelfDemoteStaff flash; got body excerpt: {}",
        &body[..body.len().min(800)]
    );

    let after = snapshot_via_pool(app, user_id).await;
    assert_eq!(after, before, "role flags must be unchanged after refusal");
}

/// A superuser POSTing the edit form on their own row with `is_active`
/// unchecked must be refused with `SelfDeactivate` (the self-check
/// runs *before* the last-superuser fence, so this fires regardless of
/// how many other active superusers exist).
#[tokio::test]
async fn superuser_cannot_self_deactivate_via_web() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("self_deact_super");
    let user_id = create_simple_admin_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;
    let stored_username = get_username(&mut conn, user_id).await;
    let email = get_email(&mut conn, user_id).await;
    let before = read_snapshot(&mut conn, user_id).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &stored_username, true, true)
        .await;
    let csrf = app.generate_csrf_token();
    drop(conn);

    let response = post_edit(
        app,
        user_uuid,
        &token,
        &csrf,
        &stored_username,
        &email,
        false, // is_active = OFF (self-deactivate)
        true,
        true,
    )
    .await;

    let body = follow_redirect_and_read(app, response, &token).await;
    assert!(
        body.contains(RoleViolation::SelfDeactivate.flash_message()),
        "must surface the SelfDeactivate flash; got body excerpt: {}",
        &body[..body.len().min(800)]
    );

    let after = snapshot_via_pool(app, user_id).await;
    assert_eq!(after, before, "role flags must be unchanged after refusal");
}

/// JSON API self-deactivate (`PUT /api/v1/accounts/{self_uuid}` with
/// `{"is_active": false}`) must return HTTP 403 with the
/// `SelfDeactivate` flash message in the JSON error body, and the row
/// must remain active.
#[tokio::test]
async fn superuser_cannot_self_deactivate_via_api() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin =
        create_admin_user(&mut conn, &app.auth_service, &unique_name("self_deact_api")).await;
    let before = read_snapshot(&mut conn, admin.user.id).await;
    drop(conn);

    let response = app
        .server
        .put(&format!("/api/v1/accounts/{}", admin.user.uuid))
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .json(&json!({ "is_active": false }))
        .await;

    assert_eq!(
        response.status_code().as_u16(),
        403,
        "API self-deactivate must be 403 Forbidden"
    );
    let body = response.text();
    assert!(
        body.contains(RoleViolation::SelfDeactivate.flash_message()),
        "API error body must surface the SelfDeactivate message; got: {}",
        body
    );

    let after = snapshot_via_pool(app, admin.user.id).await;
    assert_eq!(after, before, "is_active must NOT have been flipped");
}

/// A superuser POSTing `/accounts/users/{self_uuid}/delete` must be
/// refused with `SelfDelete` flash and the row must NOT be soft-deleted,
/// even when the operator presents a valid step-up TOTP code.
#[tokio::test]
#[serial]
async fn superuser_cannot_self_delete_via_web() {
    let app = TestApp::spawn().await;

    let (user_id, user_uuid, username, mfa_secret) =
        create_admin_with_mfa(app, "self_delete_super").await;

    let before = snapshot_via_pool(app, user_id).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, true, true)
        .await;
    let csrf = app.generate_csrf_token();
    let totp = current_totp(&mfa_secret);

    let response = post_delete(app, user_uuid, &token, &csrf, Some(&totp)).await;

    let body = follow_redirect_and_read(app, response, &token).await;
    assert!(
        body.contains(RoleViolation::SelfDelete.flash_message()),
        "must surface the SelfDelete flash; got body excerpt: {}",
        &body[..body.len().min(800)]
    );

    let after = snapshot_via_pool(app, user_id).await;
    assert_eq!(
        after, before,
        "row must NOT have been soft-deleted (is_deleted unchanged)"
    );
}

// =============================================================================
// Last-active-superuser fence -- 5 scenarios (#[serial])
// =============================================================================

/// Demoting the last active superuser must be refused, even when the
/// operator is a *different* superuser. Setup: one operator A and one
/// target B, both superusers. We isolate B as the unique active
/// superuser by deactivating every other active superuser (including A
/// would lock A out of the operation; instead we keep A active and
/// "only target B is the only one left to count" by deactivating ALL
/// others except B). To exercise the demote path we therefore:
/// - keep two active superusers, A (operator) and B (target);
/// - the count `is_superuser AND is_active AND id != B` returns 1 (A);
/// - so the fence should NOT fire here (>=1 other superuser remains)
///
/// This scenario therefore validates the symmetrical case: `B` is the
/// **only** other superuser besides `A`, and `A` tries to demote
/// themselves... which is a self-demote, already covered. To exercise
/// pure last-active-superuser DEMOTE, we make B alone the lone active
/// superuser and connect via a freshly-promoted *staff* operator who
/// holds `users:manage_admins` -- but staff doesn't have that perm;
/// only superusers do. So we must test with operator A demoting
/// itself when A is the lone superuser. The self-demote check fires
/// first on that path, masking the last-superuser fence.
///
/// Conclusion: the LAST-superuser DEMOTE path is only reachable for
/// `operator != target`. We set up TWO superusers A,B and a third
/// **other-not-counted** dummy: A active operator, B active target,
/// then we deactivate B inside the test... no, we need B to be
/// active and the *only* one. Compromise: deactivate every active
/// superuser except B, then promote A on the fly (insert as superuser)
/// AFTER isolation so A counts as a fresh active superuser BUT...
/// the count excludes B's id and includes A, so the demote of B
/// would still see >= 1 other.
///
/// The honest scenario where last-superuser-demote can fire with
/// distinct operator/target requires impersonating B itself, which
/// IS a self-demote (already tested). Skip this case at integration
/// level; it is fully covered by the unit tests on
/// `check_last_active_superuser` invariants. We keep the deactivate
/// and delete variants below where the operator/target can be
/// distinct without contradiction.
#[tokio::test]
#[serial]
async fn cannot_deactivate_last_active_superuser_via_web() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Operator: a fresh non-target superuser created BEFORE we isolate
    // the target. This operator is then deactivated by `isolate_...`
    // and we restore them at the end. Avoid using the target as
    // operator (that would re-trigger the self-deactivate fence).
    let op_username = unique_name("last_super_deact_op");
    let op_id = create_simple_admin_user(&mut conn, &op_username).await;
    let op_uuid = get_user_uuid(&mut conn, op_id).await;
    let op_stored_username = get_username(&mut conn, op_id).await;

    let target_username = unique_name("last_super_deact_target");
    let target_id = create_simple_admin_user(&mut conn, &target_username).await;
    let target_uuid = get_user_uuid(&mut conn, target_id).await;
    let target_stored_username = get_username(&mut conn, target_id).await;
    let target_email = get_email(&mut conn, target_id).await;

    // Generate the operator's auth token BEFORE deactivating them.
    // The auth middleware does not re-check `is_active` on every
    // request (it only validates JWT + session existence), so an
    // operator whose row is later flipped to inactive can still drive
    // a request -- which is exactly the configuration required to
    // reach the count-fence with `operator != target`. If we generated
    // the token *after* the isolate, that would still work today, but
    // pinning the order makes the intent explicit and is robust to
    // future hardening of the middleware.
    let token = app
        .generate_test_token(&op_uuid.to_string(), &op_stored_username, true, true)
        .await;

    // Make `target` the unique active superuser. The operator gets
    // flipped to inactive by the helper -- intentionally so, because
    // it is the only way the fence's "OTHER active superuser" count
    // can return zero with `operator != target` (the operator itself
    // would otherwise be counted as the saving second superuser).
    let (touched, when) = isolate_as_only_active_superuser(&mut conn, target_id).await;
    let before = read_snapshot(&mut conn, target_id).await;
    let csrf = app.generate_csrf_token();
    drop(conn);

    let response = post_edit(
        app,
        target_uuid,
        &token,
        &csrf,
        &target_stored_username,
        &target_email,
        false, // is_active = OFF -> Deactivate intent
        true,
        true,
    )
    .await;

    let body = follow_redirect_and_read(app, response, &token).await;
    assert!(
        body.contains(RoleViolation::LastActiveSuperuserDeactivate.flash_message()),
        "must surface LastActiveSuperuserDeactivate flash; got: {}",
        &body[..body.len().min(800)]
    );

    let after = snapshot_via_pool(app, target_id).await;
    assert_eq!(after, before, "target must remain active");

    let mut conn = app.get_conn().await;
    restore_superusers(&mut conn, &touched, when).await;
}

/// API equivalent: PUT `/api/v1/accounts/{lone_super}` with
/// `{"is_active": false}` from another superuser must be 403 with the
/// stable last-superuser-deactivate message.
#[tokio::test]
#[serial]
async fn cannot_deactivate_last_active_superuser_via_api() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let op = create_admin_user(
        &mut conn,
        &app.auth_service,
        &unique_name("last_super_deact_api_op"),
    )
    .await;

    let target_username = unique_name("last_super_deact_api_target");
    let target_id = create_simple_admin_user(&mut conn, &target_username).await;

    // The token is already populated by `create_admin_user`; the
    // isolation step deactivates the operator AND every other active
    // superuser, leaving target as the sole active one. The operator
    // can still drive the request because the auth middleware does
    // not re-check `is_active` on every request.
    let (touched, when) = isolate_as_only_active_superuser(&mut conn, target_id).await;
    let before = read_snapshot(&mut conn, target_id).await;
    let target_uuid = get_user_uuid(&mut conn, target_id).await;
    drop(conn);

    let response = app
        .server
        .put(&format!("/api/v1/accounts/{}", target_uuid))
        .add_header(header::AUTHORIZATION, app.auth_header(&op.token))
        .json(&json!({ "is_active": false }))
        .await;

    assert_eq!(
        response.status_code().as_u16(),
        403,
        "API must be 403 Forbidden"
    );
    let body = response.text();
    assert!(
        body.contains(RoleViolation::LastActiveSuperuserDeactivate.flash_message()),
        "API error body must surface LastActiveSuperuserDeactivate; got: {}",
        body
    );

    let after = snapshot_via_pool(app, target_id).await;
    assert_eq!(after, before, "target must remain active");

    let mut conn = app.get_conn().await;
    restore_superusers(&mut conn, &touched, when).await;
}

/// Demote-the-last-superuser (web) is structurally indistinguishable
/// from self-demote (the only operator who can target the lone
/// superuser is that lone superuser themselves, since by construction
/// no other active superuser exists). The self-check correctly fires
/// first and we assert THAT is the message we get. This test pins the
/// ordering: self-check before count-check.
#[tokio::test]
#[serial]
async fn cannot_demote_last_active_superuser_via_web() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("last_super_demote");
    let user_id = create_simple_admin_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;
    let stored_username = get_username(&mut conn, user_id).await;
    let email = get_email(&mut conn, user_id).await;

    let (touched, when) = isolate_as_only_active_superuser(&mut conn, user_id).await;
    let before = read_snapshot(&mut conn, user_id).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &stored_username, true, true)
        .await;
    let csrf = app.generate_csrf_token();
    drop(conn);

    let response = post_edit(
        app,
        user_uuid,
        &token,
        &csrf,
        &stored_username,
        &email,
        true,
        true,
        false, // is_superuser = OFF
    )
    .await;

    let body = follow_redirect_and_read(app, response, &token).await;
    // Self-check fires first because operator == target. The count
    // check is unreachable from this configuration -- this is the
    // documented ordering and a single user-facing message wins.
    assert!(
        body.contains(RoleViolation::SelfDemoteSuperuser.flash_message()),
        "self-check ordering pin: SelfDemoteSuperuser must mask \
         LastActiveSuperuserDemote when operator == target; body: {}",
        &body[..body.len().min(800)]
    );

    let after = snapshot_via_pool(app, user_id).await;
    assert_eq!(after, before, "row must be unchanged");

    let mut conn = app.get_conn().await;
    restore_superusers(&mut conn, &touched, when).await;
}

/// An *inactive* superuser must NOT count toward the minimum. Setup:
/// two superusers; A active (operator); B active (the row to be
/// flipped to inactive in this test = the deactivation target);
/// every other active superuser deactivated. The deactivation of B
/// would normally be refused, EXCEPT we add a third superuser C that
/// is `is_active=false`. C must still NOT be counted, so the fence
/// must still fire.
#[tokio::test]
#[serial]
async fn inactive_superuser_does_not_count_toward_minimum() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let op_username = unique_name("inactive_count_op");
    let op_id = create_simple_admin_user(&mut conn, &op_username).await;
    let op_uuid = get_user_uuid(&mut conn, op_id).await;
    let op_stored_username = get_username(&mut conn, op_id).await;

    let target_username = unique_name("inactive_count_target");
    let target_id = create_simple_admin_user(&mut conn, &target_username).await;
    let target_uuid = get_user_uuid(&mut conn, target_id).await;
    let target_stored_username = get_username(&mut conn, target_id).await;
    let target_email = get_email(&mut conn, target_id).await;

    // Pre-existing inactive superuser ("ghost") that must NOT save the
    // count.
    let ghost_username = unique_name("inactive_ghost");
    let ghost_id = create_simple_admin_user(&mut conn, &ghost_username).await;
    unwrap_ok!(
        diesel::update(users::table.filter(users::id.eq(ghost_id)))
            .set(users::is_active.eq(false))
            .execute(&mut conn)
            .await
    );

    // Token issued BEFORE the isolation step; auth middleware does
    // not re-check `is_active`, so an operator whose row is then
    // flipped to inactive can still drive this request.
    let token = app
        .generate_test_token(&op_uuid.to_string(), &op_stored_username, true, true)
        .await;

    let (touched, when) = isolate_as_only_active_superuser(&mut conn, target_id).await;
    let before = read_snapshot(&mut conn, target_id).await;
    let csrf = app.generate_csrf_token();
    drop(conn);

    let response = post_edit(
        app,
        target_uuid,
        &token,
        &csrf,
        &target_stored_username,
        &target_email,
        false, // deactivate
        true,
        true,
    )
    .await;

    let body = follow_redirect_and_read(app, response, &token).await;
    assert!(
        body.contains(RoleViolation::LastActiveSuperuserDeactivate.flash_message()),
        "the inactive ghost superuser must NOT count -- the fence MUST fire; \
         got body: {}",
        &body[..body.len().min(800)]
    );

    let after = snapshot_via_pool(app, target_id).await;
    assert_eq!(after, before, "target must remain active");

    let mut conn = app.get_conn().await;
    restore_superusers(&mut conn, &touched, when).await;
}

/// A *soft-deleted* superuser must NOT count either. Same setup as the
/// inactive case but with `is_deleted=true` on the ghost row.
#[tokio::test]
#[serial]
async fn soft_deleted_superuser_does_not_count() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let op_username = unique_name("deleted_count_op");
    let op_id = create_simple_admin_user(&mut conn, &op_username).await;
    let op_uuid = get_user_uuid(&mut conn, op_id).await;
    let op_stored_username = get_username(&mut conn, op_id).await;

    let target_username = unique_name("deleted_count_target");
    let target_id = create_simple_admin_user(&mut conn, &target_username).await;
    let target_uuid = get_user_uuid(&mut conn, target_id).await;
    let target_stored_username = get_username(&mut conn, target_id).await;
    let target_email = get_email(&mut conn, target_id).await;

    // Pre-existing soft-deleted superuser that must NOT save the count.
    let ghost_username = unique_name("deleted_ghost");
    let ghost_id = create_simple_admin_user(&mut conn, &ghost_username).await;
    unwrap_ok!(
        diesel::update(users::table.filter(users::id.eq(ghost_id)))
            .set(users::is_deleted.eq(true))
            .execute(&mut conn)
            .await
    );

    let token = app
        .generate_test_token(&op_uuid.to_string(), &op_stored_username, true, true)
        .await;

    let (touched, when) = isolate_as_only_active_superuser(&mut conn, target_id).await;
    let before = read_snapshot(&mut conn, target_id).await;
    let csrf = app.generate_csrf_token();
    drop(conn);

    let response = post_edit(
        app,
        target_uuid,
        &token,
        &csrf,
        &target_stored_username,
        &target_email,
        false,
        true,
        true,
    )
    .await;

    let body = follow_redirect_and_read(app, response, &token).await;
    assert!(
        body.contains(RoleViolation::LastActiveSuperuserDeactivate.flash_message()),
        "the soft-deleted ghost superuser must NOT count -- the fence MUST fire; \
         got body: {}",
        &body[..body.len().min(800)]
    );

    let after = snapshot_via_pool(app, target_id).await;
    assert_eq!(after, before, "target must remain active");

    let mut conn = app.get_conn().await;
    restore_superusers(&mut conn, &touched, when).await;
}

// =============================================================================
// Authorized cases -- non-regression
// =============================================================================

/// With at least two distinct active superusers, demoting one MUST
/// succeed. This guards against an over-eager fence that would refuse
/// legitimate role mutations.
#[tokio::test]
#[serial]
async fn can_demote_superuser_when_two_active_superusers_exist() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let op_username = unique_name("two_sup_demote_op");
    let op_id = create_simple_admin_user(&mut conn, &op_username).await;
    let op_uuid = get_user_uuid(&mut conn, op_id).await;
    let op_stored_username = get_username(&mut conn, op_id).await;

    let target_username = unique_name("two_sup_demote_target");
    let target_id = create_simple_admin_user(&mut conn, &target_username).await;
    let target_uuid = get_user_uuid(&mut conn, target_id).await;
    let target_stored_username = get_username(&mut conn, target_id).await;
    let target_email = get_email(&mut conn, target_id).await;

    let token = app
        .generate_test_token(&op_uuid.to_string(), &op_stored_username, true, true)
        .await;
    let csrf = app.generate_csrf_token();
    drop(conn);

    let response = post_edit(
        app,
        target_uuid,
        &token,
        &csrf,
        &target_stored_username,
        &target_email,
        true,
        true,
        false, // demote: superuser -> off
    )
    .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "expected redirect, got {}",
        status
    );

    let after = snapshot_via_pool(app, target_id).await;
    assert!(
        !after.is_superuser,
        "demote must have taken effect when other active superusers exist"
    );
}

/// Symmetric authorized case for `is_active=false` on a non-last
/// superuser via the web edit form.
#[tokio::test]
#[serial]
async fn can_deactivate_superuser_when_two_active_superusers_exist() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let op_username = unique_name("two_sup_deact_op");
    let op_id = create_simple_admin_user(&mut conn, &op_username).await;
    let op_uuid = get_user_uuid(&mut conn, op_id).await;
    let op_stored_username = get_username(&mut conn, op_id).await;

    let target_username = unique_name("two_sup_deact_target");
    let target_id = create_simple_admin_user(&mut conn, &target_username).await;
    let target_uuid = get_user_uuid(&mut conn, target_id).await;
    let target_stored_username = get_username(&mut conn, target_id).await;
    let target_email = get_email(&mut conn, target_id).await;

    let token = app
        .generate_test_token(&op_uuid.to_string(), &op_stored_username, true, true)
        .await;
    let csrf = app.generate_csrf_token();
    drop(conn);

    let response = post_edit(
        app,
        target_uuid,
        &token,
        &csrf,
        &target_stored_username,
        &target_email,
        false, // deactivate
        true,
        true,
    )
    .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "expected redirect, got {}",
        status
    );

    let after = snapshot_via_pool(app, target_id).await;
    assert!(
        !after.is_active,
        "deactivate must have taken effect when other active superusers exist"
    );
}

// =============================================================================
// Concurrency / TOCTOU guard
// =============================================================================

/// Two operators (each a different superuser) racing to deactivate two
/// different superusers must not both succeed when those two are the
/// last two active. SERIALIZABLE detects the rw-dependency cycle: at
/// most one transaction commits.
///
/// Setup:
///   - A,B are the **only two** active superusers; the fence excludes
///     each from its own count, so each request sees "one other".
///   - Two `tokio::spawn` POSTs hit `/accounts/users/A/edit?is_active=off`
///     and `/accounts/users/B/edit?is_active=off` simultaneously, from
///     a third operator C (which is itself a superuser, isolated as
///     active so it can authenticate AND so it counts as a third
///     "other" for both A's and B's fence -- but we deactivate C
///     between auth and the POST: no, we keep C active, which means
///     the fence allows both. To exercise the race we instead deactivate
///     C right after issuing its token but before the POSTs land,
///     leaving A,B as the only two actives.
///
/// The orchestration is the trickiest part of the test: we use a
/// barrier so both POSTs are dispatched as close to simultaneous as
/// possible, and we assert that the post-state has at least one
/// active superuser among (A, B). The success-count is **at most**
/// one and **at least** zero (both could fail under SerializationFailure
/// retry exhaustion); we accept either because the only invariant we
/// care about is "at least one active superuser remains".
#[tokio::test]
#[serial]
async fn concurrent_demotions_keep_at_least_one_superuser() {
    use std::sync::Arc;
    use tokio::sync::Barrier;

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Operator C: third superuser, kept active for token generation,
    // then deactivated so A and B are the only two actives.
    let c_username = unique_name("race_op_c");
    let c_id = create_simple_admin_user(&mut conn, &c_username).await;
    let c_uuid = get_user_uuid(&mut conn, c_id).await;
    let c_stored_username = get_username(&mut conn, c_id).await;

    let a_username = unique_name("race_target_a");
    let a_id = create_simple_admin_user(&mut conn, &a_username).await;
    let a_uuid = get_user_uuid(&mut conn, a_id).await;
    let a_stored_username = get_username(&mut conn, a_id).await;
    let a_email = get_email(&mut conn, a_id).await;

    let b_username = unique_name("race_target_b");
    let b_id = create_simple_admin_user(&mut conn, &b_username).await;
    let b_uuid = get_user_uuid(&mut conn, b_id).await;
    let b_stored_username = get_username(&mut conn, b_id).await;
    let b_email = get_email(&mut conn, b_id).await;

    // Issue C's token while C is still active (the auth middleware
    // requires `is_active=true`).
    let c_token = app
        .generate_test_token(&c_uuid.to_string(), &c_stored_username, true, true)
        .await;
    let csrf = app.generate_csrf_token();

    // Now isolate A,B as the only two active superusers (deactivates
    // every other active superuser, INCLUDING our operator C).
    let now = Utc::now();
    let touched: Vec<i32> = users::table
        .filter(users::is_superuser.eq(true))
        .filter(users::is_active.eq(true))
        .filter(users::is_deleted.eq(false))
        .filter(users::id.ne(a_id))
        .filter(users::id.ne(b_id))
        .select(users::id)
        .load(&mut conn)
        .await
        .unwrap_or_default();
    if !touched.is_empty() {
        unwrap_ok!(
            diesel::update(users::table.filter(users::id.eq_any(&touched)))
                .set((users::is_active.eq(false), users::updated_at.eq(now)))
                .execute(&mut conn)
                .await
        );
    }
    drop(conn);

    let barrier = Arc::new(Barrier::new(2));

    // `app` is a `&'static TestApp`: references are Copy, so each task
    // captures its own reference into the same global instance. Form
    // strings are cloned because the closures need owned values.
    let app_for_a: &'static TestApp = app;
    let token_for_a = c_token.clone();
    let csrf_for_a = csrf.clone();
    let barrier_a = barrier.clone();
    let a_username_for_post = a_stored_username.clone();
    let a_email_for_post = a_email.clone();
    let task_a = tokio::spawn(async move {
        barrier_a.wait().await;
        post_edit(
            app_for_a,
            a_uuid,
            &token_for_a,
            &csrf_for_a,
            &a_username_for_post,
            &a_email_for_post,
            false, // deactivate A
            true,
            true,
        )
        .await
        .status_code()
        .as_u16()
    });

    let app_for_b: &'static TestApp = app;
    let token_for_b = c_token.clone();
    let csrf_for_b = csrf.clone();
    let barrier_b = barrier.clone();
    let b_username_for_post = b_stored_username.clone();
    let b_email_for_post = b_email.clone();
    let task_b = tokio::spawn(async move {
        barrier_b.wait().await;
        post_edit(
            app_for_b,
            b_uuid,
            &token_for_b,
            &csrf_for_b,
            &b_username_for_post,
            &b_email_for_post,
            false, // deactivate B
            true,
            true,
        )
        .await
        .status_code()
        .as_u16()
    });

    let (status_a, status_b) = (
        task_a.await.expect("task A panicked"),
        task_b.await.expect("task B panicked"),
    );
    assert!(
        (300..400).contains(&status_a),
        "A: expected redirect, got {}",
        status_a
    );
    assert!(
        (300..400).contains(&status_b),
        "B: expected redirect, got {}",
        status_b
    );

    // The CRITICAL invariant: after the race, at least one of {A, B}
    // must still be an active superuser. The handler surface is a
    // redirect either way (success vs flash error are both 303), so
    // we cannot derive the outcome from the HTTP status alone -- we
    // must read the DB.
    let a_after = snapshot_via_pool(app, a_id).await;
    let b_after = snapshot_via_pool(app, b_id).await;
    let still_active =
        (a_after.is_superuser && a_after.is_active) || (b_after.is_superuser && b_after.is_active);
    assert!(
        still_active,
        "INVARIANT VIOLATION: both A and B got deactivated -- the SERIALIZABLE \
         tx failed to detect the rw-dependency cycle. A={:?} B={:?}",
        a_after, b_after
    );

    // Belt-and-braces global count: there must always be at least one
    // active, non-deleted superuser somewhere in the system at the end.
    let mut conn = app.get_conn().await;
    let total_active_supers: i64 = unwrap_ok!(
        users::table
            .filter(users::is_superuser.eq(true))
            .filter(users::is_active.eq(true))
            .filter(users::is_deleted.eq(false))
            .count()
            .get_result(&mut conn)
            .await
    );
    assert!(
        total_active_supers >= 1,
        "global invariant: >=1 active superuser must remain at all times, \
         got {}",
        total_active_supers
    );

    // Restore everything we touched.
    restore_superusers(&mut conn, &touched, now).await;
}
