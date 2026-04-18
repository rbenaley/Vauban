/// VAUBAN Web - Integration tests for the Edit User page.
///
/// This file covers two related concerns:
///
/// **UX-22 (issue #11): transactional confirmation message** when a password
/// is rotated via Edit User. We verify the full PRG round-trip:
///
/// 1. POST /accounts/users/{uuid} (the form submission)
/// 2. The 303 redirect Location header
/// 3. The signed `__vauban_flash` cookie set on the redirect response
/// 4. The HTML rendered on the redirect target -- the message MUST be visible,
///    not just present in a cookie
/// 5. The on-disk side effects: the password hash MUST actually change
///    when (and only when) a non-empty password is provided
///
/// **Step-up MFA (issue #11 follow-up)**: rotating any user's password
/// (including one's own) AND deleting any user requires the OPERATOR -- the
/// person currently logged in -- to confirm with a fresh TOTP code from
/// their own authenticator app. There is NO password fallback: an operator
/// without an enrolled TOTP factor is refused outright with an actionable
/// link to `/accounts/mfa/setup`. The proof is single-use within its
/// 30-second window (RFC 6238 §5.2 replay protection persisted via
/// `users.last_totp_used_window`). See [`crate::auth::step_up`] for the
/// helper, and [`vauban_web::handlers::web::users::update_user_web`] /
/// [`delete_user_web`] for the call sites.
///
/// Battle-tested matrix:
/// - happy path WITHOUT password change         -> "User updated successfully"
/// - happy path WITH password change + correct  -> "User and password updated successfully"
///   TOTP code
/// - empty password field                       -> hash unchanged, generic success
/// - password shorter than min length           -> redirect to /edit with error flash
/// - invalid CSRF token                         -> redirect with error flash, hash unchanged
/// - non-superuser editing superuser            -> rejected, no DB write
/// - non-staff user without users:write         -> rejected
/// - missing/empty totp_code                    -> rejected with explicit error
/// - wrong totp_code                            -> rejected, hash unchanged
/// - replay (same code consumed twice)          -> rejected with explicit error
/// - operator without enrolled MFA              -> rejected with link to /accounts/mfa/setup
/// - operator mfa_enabled=true, secret empty    -> rejected (degraded state)
/// - target's TOTP code as operator's code      -> rejected (operator != target)
/// - self-edit with correct TOTP                -> succeeds
/// - delete user requires step-up TOTP          -> mirror of update path
use crate::common::{TestApp, unwrap_ok, unwrap_some};
use crate::fixtures::{create_simple_admin_user, create_simple_user, unique_name};
use axum::http::header::{COOKIE, LOCATION, SET_COOKIE};
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serial_test::serial;
use uuid::Uuid;
use vauban_web::models::user::AuthSource;
use vauban_web::schema::users;
use vauban_web::services::auth::AuthService;

// =============================================================================
// Test helpers
// =============================================================================

/// Read the user UUID from a numeric user_id.
async fn get_user_uuid(conn: &mut AsyncPgConnection, user_id: i32) -> Uuid {
    unwrap_ok!(
        users::table
            .filter(users::id.eq(user_id))
            .select(users::uuid)
            .first(conn)
            .await
    )
}

/// Read the (possibly UUID-suffixed) username actually stored in DB.
async fn get_username(conn: &mut AsyncPgConnection, user_id: i32) -> String {
    unwrap_ok!(
        users::table
            .filter(users::id.eq(user_id))
            .select(users::username)
            .first(conn)
            .await
    )
}

/// Read the email actually stored in DB.
async fn get_email(conn: &mut AsyncPgConnection, user_id: i32) -> String {
    unwrap_ok!(
        users::table
            .filter(users::id.eq(user_id))
            .select(users::email)
            .first(conn)
            .await
    )
}

/// Read the current password hash for a user.
async fn get_password_hash(conn: &mut AsyncPgConnection, user_id: i32) -> String {
    unwrap_ok!(
        users::table
            .filter(users::id.eq(user_id))
            .select(users::password_hash)
            .first(conn)
            .await
    )
}

/// Read the password hash via a freshly-acquired pooled connection that is
/// released as soon as the read completes. Use this for the post-POST
/// "hash_after" assertion so the test does not hold a pool slot during the
/// follow-up GET that renders the flash banner -- under parallel test
/// execution that prevented the test server's middleware stack from getting
/// its own connection and led to spurious "/login" redirects / empty bodies.
async fn read_hash(app: &TestApp, user_id: i32) -> String {
    let mut conn = app.get_conn().await;
    get_password_hash(&mut conn, user_id).await
}

/// Read the soft-delete state (`is_deleted`) for a user.
async fn read_is_deleted(app: &TestApp, user_id: i32) -> bool {
    let mut conn = app.get_conn().await;
    unwrap_ok!(
        users::table
            .filter(users::id.eq(user_id))
            .select(users::is_deleted)
            .first(&mut conn)
            .await
    )
}

/// Extract the signed `__vauban_flash` cookie (name=value, no attributes)
/// from a response so it can be replayed on the follow-up GET.
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

/// Create an admin (is_staff + is_superuser) WITH a freshly-generated TOTP
/// secret enrolled (`mfa_enabled = true`, `mfa_secret = Some(secret)`).
/// Returns `(user_id, uuid, username, mfa_secret_base32)`.
///
/// The returned secret is what an authenticator app would have provisioned
/// from the QR code; pass it to [`current_totp_code`] to compute a code
/// that the handler will accept.
///
/// Required for any test that exercises the step-up MFA flow, because
/// `create_simple_admin_user` does not enrol MFA and would therefore hit
/// the "MFA enrollment required" branch instead of the wanted code paths.
async fn create_admin_with_mfa(app: &TestApp, label: &str) -> (i32, Uuid, String, String) {
    let username = unique_name(label);
    let user_uuid = Uuid::new_v4();
    // Use a stable Argon2 hash so other code paths that touch
    // password_hash (verify_password, etc.) don't blow up. The point of
    // this test helper is the MFA factor, not the password.
    let hash = unwrap_ok!(app.auth_service.hash_password("StableAdminPwd#2026!"));
    let (mfa_secret, _provisioning_uri) =
        unwrap_ok!(AuthService::generate_totp_secret(&username, "VAUBAN-tests"));

    // Acquire (and on transient pool errors, re-acquire) a fresh connection
    // for the INSERT itself. Holding the caller's connection across
    // setup + HTTP round-trips proved flaky under parallel test execution
    // because deadpool-diesel does not health-check pooled connections, so
    // a stale "closed" connection could be handed to us. Retry once with a
    // fresh slot before failing the test.
    let do_insert = || {
        let username = username.clone();
        let hash = hash.clone();
        let mfa_secret = mfa_secret.clone();
        async move {
            let mut conn = app.get_conn().await;
            diesel::insert_into(users::table)
                .values((
                    users::uuid.eq(user_uuid),
                    users::username.eq(&username),
                    users::email.eq(format!("{}@test.local", username)),
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
        }
    };
    let user_id: i32 = match do_insert().await {
        Ok(id) => id,
        Err(_) => unwrap_ok!(do_insert().await),
    };
    (user_id, user_uuid, username, mfa_secret)
}

/// Compute the TOTP code that the handler would accept *right now* for the
/// given base32-encoded shared secret.
fn current_totp_code(secret: &str) -> String {
    unwrap_some!(AuthService::get_current_totp(secret))
}

/// Reset `last_totp_used_window` to NULL so a test can produce two distinct
/// successful step-ups inside the same Tokio runtime tick (e.g. the replay
/// test wants to first consume a code, then re-attempt with the same code).
async fn reset_totp_replay_state(app: &TestApp, user_id: i32) {
    let mut conn = app.get_conn().await;
    unwrap_ok!(
        diesel::update(users::table.filter(users::id.eq(user_id)))
            .set(users::last_totp_used_window.eq::<Option<i64>>(None))
            .execute(&mut conn)
            .await
    );
}

/// Form payload describing an Edit User submission. Using a struct (instead of
/// a giant arg list) keeps individual tests readable AND lets us add new
/// optional fields (like `totp_code`) without rewriting every caller.
#[derive(Default)]
struct EditForm<'a> {
    username: &'a str,
    email: &'a str,
    /// New password to rotate to. `None` = field absent. `Some("")` = field
    /// present but empty (documented "keep current").
    password: Option<&'a str>,
    /// Operator's own current TOTP code (step-up MFA). `None` = field absent.
    totp_code: Option<&'a str>,
    is_active: bool,
    is_staff: bool,
    is_superuser: bool,
}

/// POST the edit form for `target_uuid` impersonating the JWT in `token`.
/// Returns the raw response so callers can assert on status / cookies.
async fn post_edit_user_form(
    app: &TestApp,
    target_uuid: Uuid,
    token: &str,
    csrf_token: &str,
    f: EditForm<'_>,
) -> axum_test::TestResponse {
    let mut form: Vec<(&str, &str)> = vec![
        ("csrf_token", csrf_token),
        ("username", f.username),
        ("email", f.email),
    ];
    if let Some(pwd) = f.password {
        form.push(("password", pwd));
    }
    if let Some(code) = f.totp_code {
        form.push(("totp_code", code));
    }
    if f.is_active {
        form.push(("is_active", "on"));
    }
    if f.is_staff {
        form.push(("is_staff", "on"));
    }
    if f.is_superuser {
        form.push(("is_superuser", "on"));
    }

    app.server
        .post(&format!("/accounts/users/{}", target_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&form)
        .await
}

/// Backwards-compatible thin wrapper used by the older UX-22 tests that
/// don't (yet) care about the step-up MFA field. Forwards to
/// [`post_edit_user_form`] with `totp_code = None`.
#[allow(clippy::too_many_arguments)]
async fn post_edit_user(
    app: &TestApp,
    target_uuid: Uuid,
    token: &str,
    csrf_token: &str,
    username: &str,
    email: &str,
    password: Option<&str>,
    is_active: bool,
    is_staff: bool,
) -> axum_test::TestResponse {
    post_edit_user_form(
        app,
        target_uuid,
        token,
        csrf_token,
        EditForm {
            username,
            email,
            password,
            totp_code: None,
            is_active,
            is_staff,
            is_superuser: false,
        },
    )
    .await
}

/// POST the delete-user form for `target_uuid` impersonating `token`.
async fn post_delete_user(
    app: &TestApp,
    target_uuid: Uuid,
    token: &str,
    csrf_token: &str,
    totp_code: Option<&str>,
) -> axum_test::TestResponse {
    let mut form: Vec<(&str, &str)> = vec![("csrf_token", csrf_token)];
    if let Some(code) = totp_code {
        form.push(("totp_code", code));
    }
    app.server
        .post(&format!("/accounts/users/{}/delete", target_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&form)
        .await
}

// =============================================================================
// UX-22 happy paths -- transactional message MUST mention the password
// =============================================================================

/// UX-22: editing a user WITHOUT touching the password field MUST emit the
/// generic "User updated successfully" message, redirect to the detail page,
/// and keep the password hash byte-for-byte identical. No MFA is required
/// because no sensitive operation is gated.
#[tokio::test]
#[serial]
async fn test_ux22_update_without_password_keeps_hash_and_shows_generic_message() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("ux22_no_pwd_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let target_id = create_simple_user(&mut conn, "ux22_no_pwd_target").await;
    let target_uuid = get_user_uuid(&mut conn, target_id).await;
    let target_username = get_username(&mut conn, target_id).await;
    let target_email = get_email(&mut conn, target_id).await;
    let hash_before = get_password_hash(&mut conn, target_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let csrf = app.generate_csrf_token();
    drop(conn);

    let response = post_edit_user(
        app,
        target_uuid,
        &token,
        &csrf,
        &target_username,
        &target_email,
        None,
        true,
        false,
    )
    .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "PRG: expected redirect, got {}",
        status
    );

    let location = response
        .headers()
        .get(LOCATION)
        .expect("redirect must carry Location")
        .to_str()
        .expect("Location must be UTF-8");
    assert_eq!(
        location,
        format!("/accounts/users/{}", target_uuid),
        "must redirect to detail page"
    );

    let hash_after = read_hash(app, target_id).await;
    assert_eq!(
        hash_after, hash_before,
        "password hash MUST NOT change when password field is absent"
    );

    let flash_cookie = extract_flash_cookie(&response).expect("flash cookie must be set");

    let detail = app
        .server
        .get(&format!("/accounts/users/{}", target_uuid))
        .add_header(COOKIE, format!("access_token={}; {}", token, flash_cookie))
        .await;
    assert_eq!(detail.status_code().as_u16(), 200);

    let body = detail.text();
    assert!(
        body.contains("User updated successfully"),
        "detail page must render the generic success banner; got: {}",
        &body[..body.len().min(800)]
    );
    assert!(
        !body.contains("password updated"),
        "must NOT claim a password change when none happened"
    );
    assert!(
        body.contains("bg-green-50"),
        "success banner must use the success Tailwind style"
    );
}

/// UX-22 core regression: editing a user WITH a new password MUST emit a
/// transactional message that explicitly mentions the password, and the hash
/// MUST actually change to a new Argon2id digest. Also validates the
/// step-up MFA composition: the operator MUST present a fresh TOTP code.
#[tokio::test]
#[serial]
async fn test_ux22_update_with_password_shows_password_message_and_rotates_hash() {
    let app = TestApp::spawn().await;

    let (_admin_id, admin_uuid, admin_name, mfa_secret) =
        create_admin_with_mfa(app, "ux22_pwd_admin").await;

    let mut conn = app.get_conn().await;
    let target_id = create_simple_user(&mut conn, "ux22_pwd_target").await;
    let target_uuid = get_user_uuid(&mut conn, target_id).await;
    let target_username = get_username(&mut conn, target_id).await;
    let target_email = get_email(&mut conn, target_id).await;
    let hash_before = get_password_hash(&mut conn, target_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let csrf = app.generate_csrf_token();
    drop(conn);

    let totp = current_totp_code(&mfa_secret);
    let new_password = "RotatedByUX22Test#2026!";
    let response = post_edit_user_form(
        app,
        target_uuid,
        &token,
        &csrf,
        EditForm {
            username: &target_username,
            email: &target_email,
            password: Some(new_password),
            totp_code: Some(&totp),
            is_active: true,
            ..Default::default()
        },
    )
    .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "PRG: expected redirect, got {}",
        status
    );
    assert_eq!(
        response
            .headers()
            .get(LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some(format!("/accounts/users/{}", target_uuid).as_str()),
        "must redirect to detail page on success"
    );

    let hash_after = read_hash(app, target_id).await;
    assert_ne!(
        hash_after, hash_before,
        "password hash MUST change after a password rotation"
    );
    assert!(
        hash_after.starts_with("$argon2"),
        "new hash MUST be Argon2 (PHC string), got prefix '{}'",
        &hash_after[..hash_after.len().min(20)]
    );

    let flash_cookie = extract_flash_cookie(&response).expect("flash cookie must be set");

    let detail = app
        .server
        .get(&format!("/accounts/users/{}", target_uuid))
        .add_header(COOKIE, format!("access_token={}; {}", token, flash_cookie))
        .await;
    assert_eq!(detail.status_code().as_u16(), 200);

    let body = detail.text();
    assert!(
        body.contains("User and password updated successfully"),
        "UX-22: detail page MUST render a transactional message that explicitly \
         mentions the password rotation; got body: {}",
        &body[..body.len().min(800)]
    );
    assert!(
        body.contains("bg-green-50"),
        "transactional confirmation must use the success Tailwind style"
    );
}

/// Empty password field is a documented "leave unchanged" signal in the
/// template ("Leave blank to keep current password"). Submitting an empty
/// string MUST therefore behave exactly like omitting the field -- no MFA
/// step-up is required because no rotation is taking place.
#[tokio::test]
#[serial]
async fn test_ux22_update_with_empty_password_does_not_rotate_hash() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("ux22_empty_pwd_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let target_id = create_simple_user(&mut conn, "ux22_empty_pwd_target").await;
    let target_uuid = get_user_uuid(&mut conn, target_id).await;
    let target_username = get_username(&mut conn, target_id).await;
    let target_email = get_email(&mut conn, target_id).await;
    let hash_before = get_password_hash(&mut conn, target_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let csrf = app.generate_csrf_token();
    drop(conn);

    let response = post_edit_user(
        app,
        target_uuid,
        &token,
        &csrf,
        &target_username,
        &target_email,
        Some(""),
        true,
        false,
    )
    .await;

    let status = response.status_code().as_u16();
    assert!(status == 302 || status == 303, "PRG redirect expected");

    let hash_after = read_hash(app, target_id).await;
    assert_eq!(
        hash_after, hash_before,
        "empty password string MUST be treated as 'no rotation'"
    );

    let flash_cookie = extract_flash_cookie(&response).expect("flash cookie expected");
    let detail = app
        .server
        .get(&format!("/accounts/users/{}", target_uuid))
        .add_header(COOKIE, format!("access_token={}; {}", token, flash_cookie))
        .await;
    let body = detail.text();
    assert!(
        body.contains("User updated successfully") && !body.contains("password updated"),
        "empty password must keep the GENERIC message, got: {}",
        &body[..body.len().min(800)]
    );
}

// =============================================================================
// Error paths -- explicit feedback MUST be shown on the edit form
// =============================================================================

/// Submitting a password shorter than `password_min_length` MUST bounce the
/// admin back to the edit form WITH a visible error flash AND must not touch
/// the database. The length check runs BEFORE the step-up MFA check so the
/// user gets the most actionable message first.
#[tokio::test]
#[serial]
async fn test_ux22_password_too_short_bounces_to_edit_with_error_flash() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("ux22_short_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let target_id = create_simple_user(&mut conn, "ux22_short_target").await;
    let target_uuid = get_user_uuid(&mut conn, target_id).await;
    let target_username = get_username(&mut conn, target_id).await;
    let target_email = get_email(&mut conn, target_id).await;
    let hash_before = get_password_hash(&mut conn, target_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let csrf = app.generate_csrf_token();
    drop(conn);

    let response = post_edit_user(
        app,
        target_uuid,
        &token,
        &csrf,
        &target_username,
        &target_email,
        Some("a"),
        true,
        false,
    )
    .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "PRG: expected redirect, got {}",
        status
    );

    let location = response
        .headers()
        .get(LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert_eq!(
        location,
        format!("/accounts/users/{}/edit", target_uuid),
        "validation failures MUST send the user back to the edit form"
    );

    let hash_after = read_hash(app, target_id).await;
    assert_eq!(
        hash_after, hash_before,
        "validation failure MUST NOT touch the password hash"
    );

    let flash_cookie = extract_flash_cookie(&response).expect("error flash cookie expected");
    let edit = app
        .server
        .get(&format!("/accounts/users/{}/edit", target_uuid))
        .add_header(COOKIE, format!("access_token={}; {}", token, flash_cookie))
        .await;
    assert_eq!(edit.status_code().as_u16(), 200);

    let body = edit.text();
    assert!(
        body.contains("Password must be at least"),
        "edit form MUST surface the explicit validation error to the admin; got: {}",
        &body[..body.len().min(800)]
    );
    assert!(
        body.contains("bg-red-50"),
        "validation error must use the error Tailwind style"
    );
}

/// CSRF mismatch MUST be rejected with an explicit error flash and MUST NOT
/// touch the password hash. CSRF check runs before the step-up MFA gate.
#[tokio::test]
#[serial]
async fn test_ux22_invalid_csrf_rejected_with_error_flash() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("ux22_csrf_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let target_id = create_simple_user(&mut conn, "ux22_csrf_target").await;
    let target_uuid = get_user_uuid(&mut conn, target_id).await;
    let target_username = get_username(&mut conn, target_id).await;
    let target_email = get_email(&mut conn, target_id).await;
    let hash_before = get_password_hash(&mut conn, target_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let real_csrf = app.generate_csrf_token();
    drop(conn);

    let response = app
        .server
        .post(&format!("/accounts/users/{}", target_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, real_csrf),
        )
        .form(&[
            ("csrf_token", "tampered-token-from-attacker"),
            ("username", target_username.as_str()),
            ("email", target_email.as_str()),
            ("password", "ValidPasswordButCsrfBad#1"),
            ("is_active", "on"),
        ])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "CSRF rejection must redirect, got {}",
        status
    );

    let hash_after = read_hash(app, target_id).await;
    assert_eq!(
        hash_after, hash_before,
        "CSRF rejection MUST NOT rotate the password"
    );

    let flash_cookie = extract_flash_cookie(&response).expect("error flash expected");
    let location = response
        .headers()
        .get(LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert_eq!(
        location,
        format!("/accounts/users/{}/edit", target_uuid),
        "CSRF rejection must bounce back to the edit form"
    );

    let edit = app
        .server
        .get(&format!("/accounts/users/{}/edit", target_uuid))
        .add_header(COOKIE, format!("access_token={}; {}", token, flash_cookie))
        .await;
    let body = edit.text();
    assert!(
        body.contains("Invalid CSRF token"),
        "edit form must surface the CSRF error; got: {}",
        &body[..body.len().min(800)]
    );
}

// =============================================================================
// Authorization regressions -- battle-tested perimeter
// =============================================================================

/// A regular (non-staff, non-superuser) user MUST NOT be able to flip another
/// user's password by POSTing the form directly. The hash MUST NOT change.
#[tokio::test]
#[serial]
async fn test_ux22_regular_user_cannot_rotate_other_user_password() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let attacker_id = create_simple_user(&mut conn, "ux22_attacker").await;
    let attacker_uuid = get_user_uuid(&mut conn, attacker_id).await;
    let attacker_name = get_username(&mut conn, attacker_id).await;

    let victim_id = create_simple_user(&mut conn, "ux22_victim").await;
    let victim_uuid = get_user_uuid(&mut conn, victim_id).await;
    let victim_username = get_username(&mut conn, victim_id).await;
    let victim_email = get_email(&mut conn, victim_id).await;
    let hash_before = get_password_hash(&mut conn, victim_id).await;

    let token = app
        .generate_test_token(&attacker_uuid.to_string(), &attacker_name, false, false)
        .await;
    let csrf = app.generate_csrf_token();
    drop(conn);

    let response = post_edit_user(
        app,
        victim_uuid,
        &token,
        &csrf,
        &victim_username,
        &victim_email,
        Some("AttackerOwnedPassword#1"),
        true,
        false,
    )
    .await;

    let status = response.status_code().as_u16();
    assert!(
        (300..400).contains(&status) || status == 403,
        "non-staff user must be denied (got {})",
        status
    );

    let hash_after = read_hash(app, victim_id).await;
    assert_eq!(
        hash_after, hash_before,
        "victim password MUST NOT change after an unauthorized POST"
    );
}

/// A staff user (non-superuser) MUST NOT be able to rotate the password of
/// a superuser account. The hash MUST NOT change.
#[tokio::test]
#[serial]
async fn test_ux22_staff_cannot_rotate_superuser_password() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let staff_username = unique_name("ux22_staff_editor");
    let staff_uuid = Uuid::new_v4();
    let staff_hash = unwrap_ok!(app.auth_service.hash_password("StaffPwd#2026"));
    unwrap_ok!(
        diesel::insert_into(users::table)
            .values((
                users::uuid.eq(staff_uuid),
                users::username.eq(&staff_username),
                users::email.eq(format!("{}@test.local", staff_username)),
                users::password_hash.eq(&staff_hash),
                users::is_active.eq(true),
                users::is_staff.eq(true),
                users::is_superuser.eq(false),
                users::auth_source.eq(AuthSource::Local),
                users::preferences.eq(serde_json::json!({})),
            ))
            .execute(&mut conn)
            .await
    );

    let super_id = create_simple_admin_user(&mut conn, "ux22_super_victim").await;
    let super_uuid = get_user_uuid(&mut conn, super_id).await;
    let super_username = get_username(&mut conn, super_id).await;
    let super_email = get_email(&mut conn, super_id).await;
    let hash_before = get_password_hash(&mut conn, super_id).await;

    let token = app
        .generate_test_token(&staff_uuid.to_string(), &staff_username, false, true)
        .await;
    let csrf = app.generate_csrf_token();
    drop(conn);

    let response = post_edit_user(
        app,
        super_uuid,
        &token,
        &csrf,
        &super_username,
        &super_email,
        Some("StaffShouldNotRotateThis#1"),
        true,
        true,
    )
    .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "expected guarded redirect, got {}",
        status
    );

    let hash_after = read_hash(app, super_id).await;
    assert_eq!(
        hash_after, hash_before,
        "superuser password MUST NOT be rotated by a staff user"
    );

    let flash_cookie = extract_flash_cookie(&response).expect("flash cookie expected");
    let detail = app
        .server
        .get(&format!("/accounts/users/{}", super_uuid))
        .add_header(COOKIE, format!("access_token={}; {}", token, flash_cookie))
        .await;
    let body = detail.text();
    assert!(
        body.contains("Only a superuser can edit superuser accounts"),
        "guard message must be visible to the staff user; got: {}",
        &body[..body.len().min(800)]
    );
}

// =============================================================================
// Template structural guard -- ensures the success message never silently
// regresses to the previous generic wording when a password is rotated.
// =============================================================================

/// Compile-time-style guard against future regressions of the wording.
/// We intentionally test the source of the handler so that someone who
/// edits the success message in `users.rs` is forced to update this test
/// (and therefore think about UX-22) instead of silently breaking it.
#[test]
fn test_ux22_handler_source_contains_password_specific_message() {
    let src = include_str!("../../src/handlers/web/users.rs");
    assert!(
        src.contains("\"User and password updated successfully\""),
        "UX-22 regression: update_user_web MUST emit \
         'User and password updated successfully' when a password is rotated"
    );
    assert!(
        src.contains("\"User updated successfully\""),
        "UX-22 regression: update_user_web MUST keep \
         'User updated successfully' for non-password updates"
    );
}

// =============================================================================
// Step-up MFA matrix -- battle-tested
// =============================================================================
//
// These tests pin the contract of the step-up MFA flow on the Edit User page:
// any password rotation MUST be confirmed by the OPERATOR (the person whose
// session is making the request) presenting a fresh, single-use TOTP code
// from THEIR OWN authenticator app. This guards against:
//  * a hijacked browser session silently flipping any user's credential
//  * a replay attack within the 30-second TOTP window
//  * an operator without an enrolled second factor performing rotations
//  * confusion between operator and target authenticators
//
// Every test below also documents WHY the rule is in place, so that future
// maintainers (or future me) understand which class of attack would slip
// through if the assertion regresses.

/// Step-up happy path: operator provides a valid TOTP code from their own
/// secret and the rotation goes through, hash changes, success banner shown.
#[tokio::test]
#[serial]
async fn test_mfa_correct_totp_succeeds() {
    let app = TestApp::spawn().await;
    let (_op_id, op_uuid, op_name, mfa_secret) = create_admin_with_mfa(app, "mfa_ok_op").await;

    let mut conn = app.get_conn().await;
    let target_id = create_simple_user(&mut conn, "mfa_ok_target").await;
    let target_uuid = get_user_uuid(&mut conn, target_id).await;
    let target_username = get_username(&mut conn, target_id).await;
    let target_email = get_email(&mut conn, target_id).await;
    let hash_before = get_password_hash(&mut conn, target_id).await;

    let token = app
        .generate_test_token(&op_uuid.to_string(), &op_name, true, true)
        .await;
    let csrf = app.generate_csrf_token();
    drop(conn);

    let totp = current_totp_code(&mfa_secret);
    let response = post_edit_user_form(
        app,
        target_uuid,
        &token,
        &csrf,
        EditForm {
            username: &target_username,
            email: &target_email,
            password: Some("BrandNewTargetPwd#2026"),
            totp_code: Some(&totp),
            is_active: true,
            ..Default::default()
        },
    )
    .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "expected redirect, got {}",
        status
    );
    assert_eq!(
        response
            .headers()
            .get(LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some(format!("/accounts/users/{}", target_uuid).as_str()),
        "successful rotation must redirect to the detail page"
    );

    let hash_after = read_hash(app, target_id).await;
    assert_ne!(
        hash_after, hash_before,
        "hash MUST change on a successful rotation"
    );
    assert!(
        hash_after.starts_with("$argon2"),
        "new hash must be Argon2id PHC"
    );
}

/// Step-up missing: a password rotation request that omits `totp_code`
/// MUST be rejected, the hash MUST NOT change, and the operator MUST be
/// bounced back to the edit form with an explicit error flash.
#[tokio::test]
#[serial]
async fn test_mfa_missing_totp_rejected() {
    let app = TestApp::spawn().await;
    let (_op_id, op_uuid, op_name, _secret) = create_admin_with_mfa(app, "mfa_missing_op").await;

    let mut conn = app.get_conn().await;
    let target_id = create_simple_user(&mut conn, "mfa_missing_target").await;
    let target_uuid = get_user_uuid(&mut conn, target_id).await;
    let target_username = get_username(&mut conn, target_id).await;
    let target_email = get_email(&mut conn, target_id).await;
    let hash_before = get_password_hash(&mut conn, target_id).await;

    let token = app
        .generate_test_token(&op_uuid.to_string(), &op_name, true, true)
        .await;
    let csrf = app.generate_csrf_token();
    drop(conn);

    let response = post_edit_user_form(
        app,
        target_uuid,
        &token,
        &csrf,
        EditForm {
            username: &target_username,
            email: &target_email,
            password: Some("AttemptedRotation#1"),
            totp_code: None,
            is_active: true,
            ..Default::default()
        },
    )
    .await;

    let status = response.status_code().as_u16();
    assert!(status == 302 || status == 303);
    assert_eq!(
        response
            .headers()
            .get(LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some(format!("/accounts/users/{}/edit", target_uuid).as_str()),
        "missing step-up must bounce back to the edit form, not the detail page"
    );

    let hash_after = read_hash(app, target_id).await;
    assert_eq!(
        hash_after, hash_before,
        "missing step-up MUST NOT touch the password hash"
    );

    let flash = extract_flash_cookie(&response).expect("error flash expected");
    let edit = app
        .server
        .get(&format!("/accounts/users/{}/edit", target_uuid))
        .add_header(COOKIE, format!("access_token={}; {}", token, flash))
        .await;
    let body = edit.text();
    assert!(
        body.contains("Please enter your authenticator code"),
        "edit form must surface the explicit step-up requirement, got: {}",
        &body[..body.len().min(800)]
    );
    assert!(body.contains("bg-red-50"), "must use error Tailwind style");
}

/// Step-up empty string: an explicit empty `totp_code` MUST be treated like
/// a missing one (same explicit error, no DB write). Pins the behaviour so
/// a future refactor doesn't accidentally make `Some("")` a pass-through.
#[tokio::test]
#[serial]
async fn test_mfa_empty_totp_rejected() {
    let app = TestApp::spawn().await;
    let (_op_id, op_uuid, op_name, _secret) = create_admin_with_mfa(app, "mfa_empty_op").await;

    let mut conn = app.get_conn().await;
    let target_id = create_simple_user(&mut conn, "mfa_empty_target").await;
    let target_uuid = get_user_uuid(&mut conn, target_id).await;
    let target_username = get_username(&mut conn, target_id).await;
    let target_email = get_email(&mut conn, target_id).await;
    let hash_before = get_password_hash(&mut conn, target_id).await;

    let token = app
        .generate_test_token(&op_uuid.to_string(), &op_name, true, true)
        .await;
    let csrf = app.generate_csrf_token();
    drop(conn);

    let response = post_edit_user_form(
        app,
        target_uuid,
        &token,
        &csrf,
        EditForm {
            username: &target_username,
            email: &target_email,
            password: Some("AttemptedRotation#2"),
            totp_code: Some(""),
            is_active: true,
            ..Default::default()
        },
    )
    .await;

    assert_eq!(
        response
            .headers()
            .get(LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some(format!("/accounts/users/{}/edit", target_uuid).as_str()),
    );
    let hash_after = read_hash(app, target_id).await;
    assert_eq!(
        hash_after, hash_before,
        "empty totp_code is NOT a free pass"
    );
}

/// Step-up wrong: a non-empty but incorrect `totp_code` MUST be rejected
/// with the dedicated "Authenticator code is incorrect." flash, and the
/// target hash MUST stay unchanged.
#[tokio::test]
#[serial]
async fn test_mfa_wrong_totp_rejected() {
    let app = TestApp::spawn().await;
    let (_op_id, op_uuid, op_name, _secret) = create_admin_with_mfa(app, "mfa_wrong_op").await;

    let mut conn = app.get_conn().await;
    let target_id = create_simple_user(&mut conn, "mfa_wrong_target").await;
    let target_uuid = get_user_uuid(&mut conn, target_id).await;
    let target_username = get_username(&mut conn, target_id).await;
    let target_email = get_email(&mut conn, target_id).await;
    let hash_before = get_password_hash(&mut conn, target_id).await;

    let token = app
        .generate_test_token(&op_uuid.to_string(), &op_name, true, true)
        .await;
    let csrf = app.generate_csrf_token();
    drop(conn);

    let response = post_edit_user_form(
        app,
        target_uuid,
        &token,
        &csrf,
        EditForm {
            username: &target_username,
            email: &target_email,
            password: Some("StolenSessionRotation#1"),
            totp_code: Some("000000"),
            is_active: true,
            ..Default::default()
        },
    )
    .await;

    assert_eq!(
        response
            .headers()
            .get(LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some(format!("/accounts/users/{}/edit", target_uuid).as_str()),
        "wrong totp_code must bounce to the edit form"
    );
    let hash_after = read_hash(app, target_id).await;
    assert_eq!(
        hash_after, hash_before,
        "wrong totp_code MUST NOT rotate the target hash"
    );

    let flash = extract_flash_cookie(&response).expect("error flash expected");
    let edit = app
        .server
        .get(&format!("/accounts/users/{}/edit", target_uuid))
        .add_header(COOKIE, format!("access_token={}; {}", token, flash))
        .await;
    let body = edit.text();
    assert!(
        body.contains("Authenticator code is incorrect"),
        "edit form must surface the explicit wrong-code error, got: {}",
        &body[..body.len().min(800)]
    );
}

/// Replay protection (RFC 6238 §5.2): once a code has been consumed by the
/// step-up flow, the SAME code MUST be refused even if the 30-second window
/// is still open. This closes the window where an attacker who intercepts
/// a valid code could replay it on another sensitive operation before it
/// expires.
#[tokio::test]
#[serial]
async fn test_mfa_replay_attack_rejected() {
    let app = TestApp::spawn().await;
    let (_op_id, op_uuid, op_name, mfa_secret) = create_admin_with_mfa(app, "mfa_replay_op").await;

    let mut conn = app.get_conn().await;
    let target1_id = create_simple_user(&mut conn, "mfa_replay_t1").await;
    let target1_uuid = get_user_uuid(&mut conn, target1_id).await;
    let target1_username = get_username(&mut conn, target1_id).await;
    let target1_email = get_email(&mut conn, target1_id).await;

    let target2_id = create_simple_user(&mut conn, "mfa_replay_t2").await;
    let target2_uuid = get_user_uuid(&mut conn, target2_id).await;
    let target2_username = get_username(&mut conn, target2_id).await;
    let target2_email = get_email(&mut conn, target2_id).await;
    let target2_hash_before = get_password_hash(&mut conn, target2_id).await;

    let token = app
        .generate_test_token(&op_uuid.to_string(), &op_name, true, true)
        .await;
    let csrf = app.generate_csrf_token();
    drop(conn);

    // First successful rotation consumes the code.
    let totp = current_totp_code(&mfa_secret);
    let r1 = post_edit_user_form(
        app,
        target1_uuid,
        &token,
        &csrf,
        EditForm {
            username: &target1_username,
            email: &target1_email,
            password: Some("FirstRotation#2026"),
            totp_code: Some(&totp),
            is_active: true,
            ..Default::default()
        },
    )
    .await;
    assert_eq!(
        r1.headers().get(LOCATION).and_then(|v| v.to_str().ok()),
        Some(format!("/accounts/users/{}", target1_uuid).as_str()),
        "first rotation must succeed (sanity check before replay attempt)"
    );

    // Same code, second sensitive op -- MUST be refused as replay.
    let r2 = post_edit_user_form(
        app,
        target2_uuid,
        &token,
        &csrf,
        EditForm {
            username: &target2_username,
            email: &target2_email,
            password: Some("ReplayedRotation#2026"),
            totp_code: Some(&totp),
            is_active: true,
            ..Default::default()
        },
    )
    .await;
    assert_eq!(
        r2.headers().get(LOCATION).and_then(|v| v.to_str().ok()),
        Some(format!("/accounts/users/{}/edit", target2_uuid).as_str()),
        "replayed TOTP code MUST be rejected"
    );

    let target2_hash_after = read_hash(app, target2_id).await;
    assert_eq!(
        target2_hash_after, target2_hash_before,
        "replayed code MUST NOT rotate the second target's hash"
    );

    let flash = extract_flash_cookie(&r2).expect("error flash expected on replay");
    let edit = app
        .server
        .get(&format!("/accounts/users/{}/edit", target2_uuid))
        .add_header(COOKIE, format!("access_token={}; {}", token, flash))
        .await;
    let body = edit.text();
    assert!(
        body.contains("already been used"),
        "replay error wording must be explicit, got: {}",
        &body[..body.len().min(800)]
    );
}

/// CRITICAL non-confusion test: the verification is against the OPERATOR's
/// secret, not the TARGET's. Passing a code generated from the target's
/// authenticator MUST be rejected -- otherwise an attacker who somehow
/// learned the target's TOTP could rotate the target's password through any
/// hijacked admin session (or via a malicious operator account).
#[tokio::test]
#[serial]
async fn test_mfa_target_totp_not_accepted_as_operator_totp() {
    let app = TestApp::spawn().await;
    let (_op_id, op_uuid, op_name, _op_secret) =
        create_admin_with_mfa(app, "mfa_distinct_op").await;
    let (target_id, target_uuid, target_username, target_secret) =
        create_admin_with_mfa(app, "mfa_distinct_target").await;

    let mut conn = app.get_conn().await;
    unwrap_ok!(
        diesel::update(users::table.filter(users::id.eq(target_id)))
            .set((users::is_staff.eq(false), users::is_superuser.eq(false)))
            .execute(&mut conn)
            .await
    );
    let target_email = get_email(&mut conn, target_id).await;
    let hash_before = get_password_hash(&mut conn, target_id).await;

    let token = app
        .generate_test_token(&op_uuid.to_string(), &op_name, true, true)
        .await;
    let csrf = app.generate_csrf_token();
    drop(conn);

    let target_code = current_totp_code(&target_secret);
    let response = post_edit_user_form(
        app,
        target_uuid,
        &token,
        &csrf,
        EditForm {
            username: &target_username,
            email: &target_email,
            password: Some("ShouldNotApply#1"),
            totp_code: Some(&target_code),
            is_active: true,
            ..Default::default()
        },
    )
    .await;

    assert_eq!(
        response
            .headers()
            .get(LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some(format!("/accounts/users/{}/edit", target_uuid).as_str()),
        "operator-vs-target confusion attack must be rejected"
    );
    let hash_after = read_hash(app, target_id).await;
    assert_eq!(
        hash_after, hash_before,
        "target hash MUST NOT change when the operator passes the target's TOTP code"
    );
}

/// Operator without an enrolled TOTP factor (mfa_enabled = false) MUST NOT
/// be allowed to rotate -- there is no password fallback in this design.
/// The user-facing message MUST point to /accounts/mfa/setup.
#[tokio::test]
#[serial]
async fn test_mfa_operator_without_enrolled_mfa_rejected_with_actionable_message() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // create_simple_admin_user does NOT enrol MFA -- exactly the case we want.
    let admin_name = unique_name("mfa_no_enroll_op");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let target_id = create_simple_user(&mut conn, "mfa_no_enroll_target").await;
    let target_uuid = get_user_uuid(&mut conn, target_id).await;
    let target_username = get_username(&mut conn, target_id).await;
    let target_email = get_email(&mut conn, target_id).await;
    let hash_before = get_password_hash(&mut conn, target_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let csrf = app.generate_csrf_token();
    drop(conn);

    let response = post_edit_user_form(
        app,
        target_uuid,
        &token,
        &csrf,
        EditForm {
            username: &target_username,
            email: &target_email,
            password: Some("AttemptFromUnenrolledOp#1"),
            totp_code: Some("123456"),
            is_active: true,
            ..Default::default()
        },
    )
    .await;

    assert_eq!(
        response
            .headers()
            .get(LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some(format!("/accounts/users/{}/edit", target_uuid).as_str()),
    );
    let hash_after = read_hash(app, target_id).await;
    assert_eq!(
        hash_after, hash_before,
        "operator without enrolled MFA MUST NOT rotate any password"
    );

    let flash = extract_flash_cookie(&response).expect("error flash expected");
    let edit = app
        .server
        .get(&format!("/accounts/users/{}/edit", target_uuid))
        .add_header(COOKIE, format!("access_token={}; {}", token, flash))
        .await;
    let body = edit.text();
    assert!(
        body.contains("MFA enrollment required"),
        "operator without MFA must see the explicit refusal, got: {}",
        &body[..body.len().min(800)]
    );
    assert!(
        body.contains("/accounts/mfa/setup"),
        "the error must offer an actionable link to enrol MFA"
    );
}

/// Degraded state: operator has `mfa_enabled = true` but `mfa_secret` is
/// somehow NULL/empty (data corruption, half-finished enrollment, downgrade
/// attack). MUST be treated as "not enrolled" rather than as a free pass.
#[tokio::test]
#[serial]
async fn test_mfa_operator_with_mfa_enabled_but_empty_secret_rejected() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("mfa_corrupt_op");
    let admin_uuid = Uuid::new_v4();
    let admin_hash = unwrap_ok!(app.auth_service.hash_password("AdminPwd#2026"));
    let admin_id: i32 = unwrap_ok!(
        diesel::insert_into(users::table)
            .values((
                users::uuid.eq(admin_uuid),
                users::username.eq(&admin_name),
                users::email.eq(format!("{}@test.local", admin_name)),
                users::password_hash.eq(&admin_hash),
                users::is_active.eq(true),
                users::is_staff.eq(true),
                users::is_superuser.eq(true),
                users::mfa_enabled.eq(true),
                users::mfa_secret.eq::<Option<String>>(None),
                users::auth_source.eq(AuthSource::Local),
                users::preferences.eq(serde_json::json!({})),
            ))
            .returning(users::id)
            .get_result(&mut conn)
            .await
    );
    let _ = admin_id;

    let target_id = create_simple_user(&mut conn, "mfa_corrupt_target").await;
    let target_uuid = get_user_uuid(&mut conn, target_id).await;
    let target_username = get_username(&mut conn, target_id).await;
    let target_email = get_email(&mut conn, target_id).await;
    let hash_before = get_password_hash(&mut conn, target_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let csrf = app.generate_csrf_token();
    drop(conn);

    let response = post_edit_user_form(
        app,
        target_uuid,
        &token,
        &csrf,
        EditForm {
            username: &target_username,
            email: &target_email,
            password: Some("AttemptFromCorruptOp#1"),
            totp_code: Some("123456"),
            is_active: true,
            ..Default::default()
        },
    )
    .await;

    assert_eq!(
        response
            .headers()
            .get(LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some(format!("/accounts/users/{}/edit", target_uuid).as_str()),
    );
    let hash_after = read_hash(app, target_id).await;
    assert_eq!(
        hash_after, hash_before,
        "operator with mfa_enabled=true but no secret MUST be refused"
    );
}

/// Self-edit: when the operator is editing their OWN account the same rule
/// applies -- they must enter THEIR own current TOTP code to authorise the
/// rotation. (Operator and target happen to be the same row here.)
#[tokio::test]
#[serial]
async fn test_mfa_self_edit_with_correct_totp_succeeds() {
    let app = TestApp::spawn().await;
    let (op_id, op_uuid, op_name, mfa_secret) = create_admin_with_mfa(app, "mfa_self_op").await;

    let mut conn = app.get_conn().await;
    let op_email = get_email(&mut conn, op_id).await;
    let hash_before = get_password_hash(&mut conn, op_id).await;

    let token = app
        .generate_test_token(&op_uuid.to_string(), &op_name, true, true)
        .await;
    let csrf = app.generate_csrf_token();
    drop(conn);

    let totp = current_totp_code(&mfa_secret);
    let new_pwd = "MyBrandNewOwnPwd#2026!";
    let response = post_edit_user_form(
        app,
        op_uuid,
        &token,
        &csrf,
        EditForm {
            username: &op_name,
            email: &op_email,
            password: Some(new_pwd),
            totp_code: Some(&totp),
            is_active: true,
            is_staff: true,
            is_superuser: true,
        },
    )
    .await;

    assert_eq!(
        response
            .headers()
            .get(LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some(format!("/accounts/users/{}", op_uuid).as_str()),
        "successful self-edit must redirect to own detail page"
    );

    let hash_after = read_hash(app, op_id).await;
    assert_ne!(hash_after, hash_before, "own hash must rotate on self-edit");

    let verifies = unwrap_ok!(app.auth_service.verify_password(new_pwd, &hash_after));
    assert!(verifies, "new password must verify against the new hash");
}

/// Self-edit with the WRONG TOTP code MUST be refused -- this is the most
/// likely user-facing failure mode and must produce a clear error.
#[tokio::test]
#[serial]
async fn test_mfa_self_edit_with_wrong_totp_rejected() {
    let app = TestApp::spawn().await;
    let (op_id, op_uuid, op_name, _secret) = create_admin_with_mfa(app, "mfa_self_wrong_op").await;

    let mut conn = app.get_conn().await;
    let op_email = get_email(&mut conn, op_id).await;
    let hash_before = get_password_hash(&mut conn, op_id).await;

    let token = app
        .generate_test_token(&op_uuid.to_string(), &op_name, true, true)
        .await;
    let csrf = app.generate_csrf_token();
    drop(conn);

    let response = post_edit_user_form(
        app,
        op_uuid,
        &token,
        &csrf,
        EditForm {
            username: &op_name,
            email: &op_email,
            password: Some("NewOwnPwd#2026!"),
            totp_code: Some("000000"),
            is_active: true,
            is_staff: true,
            is_superuser: true,
        },
    )
    .await;

    assert_eq!(
        response
            .headers()
            .get(LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some(format!("/accounts/users/{}/edit", op_uuid).as_str()),
        "wrong own code must bounce to the self edit form"
    );
    let hash_after = read_hash(app, op_id).await;
    assert_eq!(
        hash_after, hash_before,
        "own hash MUST NOT change with wrong step-up"
    );
}

/// Regression guard: NOT touching the password field MUST NOT require a
/// TOTP code. The step-up prompt is gated entirely on the rotation intent.
/// An operator without enrolled MFA must therefore still be able to edit
/// non-credential fields (display name, etc.).
#[tokio::test]
#[serial]
async fn test_mfa_not_required_when_password_field_omitted() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("mfa_no_pwd_op");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let target_id = create_simple_user(&mut conn, "mfa_no_pwd_target").await;
    let target_uuid = get_user_uuid(&mut conn, target_id).await;
    let target_username = get_username(&mut conn, target_id).await;
    let target_email = get_email(&mut conn, target_id).await;
    let hash_before = get_password_hash(&mut conn, target_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let csrf = app.generate_csrf_token();
    drop(conn);

    let response = post_edit_user_form(
        app,
        target_uuid,
        &token,
        &csrf,
        EditForm {
            username: &target_username,
            email: &target_email,
            password: None,
            totp_code: None,
            is_active: true,
            ..Default::default()
        },
    )
    .await;

    assert_eq!(
        response
            .headers()
            .get(LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some(format!("/accounts/users/{}", target_uuid).as_str()),
        "non-rotation update must succeed without totp_code"
    );
    let hash_after = read_hash(app, target_id).await;
    assert_eq!(
        hash_after, hash_before,
        "non-rotation update MUST NOT touch the hash"
    );
}

/// Same regression as above but with `password=""`. The empty string is the
/// documented "keep current password" sentinel -- it MUST also not require
/// a TOTP code.
#[tokio::test]
#[serial]
async fn test_mfa_not_required_when_password_field_is_empty_string() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("mfa_empty_pwd_op");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let target_id = create_simple_user(&mut conn, "mfa_empty_pwd_target").await;
    let target_uuid = get_user_uuid(&mut conn, target_id).await;
    let target_username = get_username(&mut conn, target_id).await;
    let target_email = get_email(&mut conn, target_id).await;
    let hash_before = get_password_hash(&mut conn, target_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let csrf = app.generate_csrf_token();
    drop(conn);

    let response = post_edit_user_form(
        app,
        target_uuid,
        &token,
        &csrf,
        EditForm {
            username: &target_username,
            email: &target_email,
            password: Some(""),
            totp_code: None,
            is_active: true,
            ..Default::default()
        },
    )
    .await;

    assert_eq!(
        response
            .headers()
            .get(LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some(format!("/accounts/users/{}", target_uuid).as_str()),
        "empty password sentinel must not trigger the step-up prompt"
    );
    let hash_after = read_hash(app, target_id).await;
    assert_eq!(hash_after, hash_before);
}

/// Length validation runs BEFORE the step-up MFA check so the user gets
/// the most actionable message first. Sending a too-short password without
/// a `totp_code` MUST surface the length error (not the missing-step-up
/// error), and the hash MUST NOT change.
#[tokio::test]
#[serial]
async fn test_mfa_min_length_takes_precedence_over_missing_totp_code() {
    let app = TestApp::spawn().await;
    let (_op_id, op_uuid, op_name, _secret) = create_admin_with_mfa(app, "mfa_short_op").await;

    let mut conn = app.get_conn().await;
    let target_id = create_simple_user(&mut conn, "mfa_short_target").await;
    let target_uuid = get_user_uuid(&mut conn, target_id).await;
    let target_username = get_username(&mut conn, target_id).await;
    let target_email = get_email(&mut conn, target_id).await;
    let hash_before = get_password_hash(&mut conn, target_id).await;

    let token = app
        .generate_test_token(&op_uuid.to_string(), &op_name, true, true)
        .await;
    let csrf = app.generate_csrf_token();
    drop(conn);

    let response = post_edit_user_form(
        app,
        target_uuid,
        &token,
        &csrf,
        EditForm {
            username: &target_username,
            email: &target_email,
            password: Some("a"),
            totp_code: None,
            is_active: true,
            ..Default::default()
        },
    )
    .await;

    let flash = extract_flash_cookie(&response).expect("error flash expected");
    let edit = app
        .server
        .get(&format!("/accounts/users/{}/edit", target_uuid))
        .add_header(COOKIE, format!("access_token={}; {}", token, flash))
        .await;
    let body = edit.text();
    assert!(
        body.contains("Password must be at least"),
        "min-length error must take precedence over the missing-step-up error"
    );
    assert!(
        !body.contains("Please enter your authenticator code"),
        "we must NOT also show the step-up prompt error here"
    );
    let hash_after = read_hash(app, target_id).await;
    assert_eq!(hash_after, hash_before);
}

/// Form rendering: the GET /edit page MUST expose the `totp_code` field
/// with the right name, the right Alpine guard, and the right autocomplete
/// hint, otherwise the step-up contract is unenforceable from the UI.
#[tokio::test]
#[serial]
async fn test_mfa_edit_form_renders_totp_input_when_operator_has_mfa() {
    let app = TestApp::spawn().await;
    let (_op_id, op_uuid, op_name, _secret) = create_admin_with_mfa(app, "mfa_render_op").await;

    let mut conn = app.get_conn().await;
    let target_id = create_simple_user(&mut conn, "mfa_render_target").await;
    let target_uuid = get_user_uuid(&mut conn, target_id).await;

    let token = app
        .generate_test_token(&op_uuid.to_string(), &op_name, true, true)
        .await;
    drop(conn);

    let response = app
        .server
        .get(&format!("/accounts/users/{}/edit", target_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_eq!(response.status_code().as_u16(), 200);

    let body = response.text();
    assert!(
        body.contains(r#"name="totp_code""#),
        "edit form MUST expose a `totp_code` input"
    );
    assert!(
        body.contains(r#"id="totp_code""#),
        "edit form MUST give the totp_code input a stable id"
    );
    assert!(
        body.contains(r#"autocomplete="one-time-code""#),
        "edit form MUST hint browsers to autofill an OTP code"
    );
    assert!(
        body.contains(r#"inputmode="numeric""#),
        "edit form MUST hint mobile browsers to use the numeric keyboard"
    );
    assert!(
        body.contains(r#"pattern="[0-9]{6}""#),
        "edit form MUST constrain the totp_code input to exactly 6 digits"
    );
    assert!(
        body.contains(r#"autocomplete="new-password""#),
        "edit form MUST hint browsers to suggest a new password for the rotation field"
    );
    assert!(
        body.contains(":required=\"newPwd.length > 0\""),
        "totp_code MUST become required only when a new password is being typed"
    );
    assert!(
        body.contains("x-show=\"newPwd.length > 0\""),
        "the step-up prompt MUST be hidden until a rotation is being attempted"
    );
    assert!(
        !body.contains("data-testid=\"mfa-enrollment-required-banner\""),
        "an MFA-enrolled operator MUST NOT see the enrollment banner"
    );
}

/// Form rendering: an operator WITHOUT enrolled MFA MUST see an actionable
/// banner pointing to /accounts/mfa/setup AND must have the password input
/// disabled (so the UI matches the server-side enforcement).
#[tokio::test]
#[serial]
async fn test_mfa_edit_form_shows_enrollment_banner_when_operator_has_no_mfa() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("mfa_banner_op");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let target_id = create_simple_user(&mut conn, "mfa_banner_target").await;
    let target_uuid = get_user_uuid(&mut conn, target_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    drop(conn);

    let response = app
        .server
        .get(&format!("/accounts/users/{}/edit", target_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_eq!(response.status_code().as_u16(), 200);

    let body = response.text();
    assert!(
        body.contains(r#"data-testid="mfa-enrollment-required-banner""#),
        "operator without MFA MUST see the enrollment banner"
    );
    assert!(
        body.contains("MFA enrollment required to change passwords"),
        "the banner MUST carry the explicit headline"
    );
    assert!(
        body.contains(r#"href="/accounts/mfa/setup""#),
        "the banner MUST offer an actionable link to enrol MFA"
    );
    assert!(
        !body.contains(r#"name="totp_code""#),
        "operator without MFA MUST NOT see the totp_code input"
    );
}

/// Structural source guard: prevent silent regressions of the step-up MFA
/// logic by pinning the key strings that the test matrix above asserts on.
#[test]
fn test_mfa_handler_source_contains_required_strings() {
    let src = include_str!("../../src/handlers/web/users.rs");
    assert!(
        src.contains("totp_code"),
        "update_user_web MUST read a `totp_code` field"
    );
    assert!(
        src.contains("enforce_totp_step_up"),
        "update_user_web MUST delegate step-up enforcement to crate::auth::step_up"
    );

    let step_up_src = include_str!("../../src/auth/step_up.rs");
    assert!(
        step_up_src.contains("MFA enrollment required to perform this action"),
        "MFA-not-enrolled error wording is part of the public UX contract"
    );
    assert!(
        step_up_src.contains("Please enter your authenticator code to confirm"),
        "missing-code error wording is part of the public UX contract"
    );
    assert!(
        step_up_src.contains("Authenticator code is incorrect"),
        "wrong-code error wording is part of the public UX contract"
    );
    assert!(
        step_up_src.contains("already been used"),
        "replay error wording is part of the public UX contract"
    );
}

// =============================================================================
// Delete user step-up matrix
// =============================================================================
//
// Deleting a user is at least as sensitive as rotating their password (it
// is irreversible modulo the soft-delete fence). The same step-up MFA
// contract therefore applies. These tests pin the contract for the
// `delete_user_web` handler so the two code paths cannot drift.

/// Delete happy path: operator with valid TOTP can delete a user.
#[tokio::test]
#[serial]
async fn test_delete_user_with_correct_totp_succeeds() {
    let app = TestApp::spawn().await;
    let (_op_id, op_uuid, op_name, mfa_secret) = create_admin_with_mfa(app, "del_ok_op").await;

    let mut conn = app.get_conn().await;
    let target_id = create_simple_user(&mut conn, "del_ok_target").await;
    let target_uuid = get_user_uuid(&mut conn, target_id).await;

    let token = app
        .generate_test_token(&op_uuid.to_string(), &op_name, true, true)
        .await;
    let csrf = app.generate_csrf_token();
    drop(conn);

    let totp = current_totp_code(&mfa_secret);
    let response = post_delete_user(app, target_uuid, &token, &csrf, Some(&totp)).await;
    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "expected redirect, got {}",
        status
    );
    assert_eq!(
        response
            .headers()
            .get(LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/accounts/users"),
        "successful deletion must redirect to the user list"
    );
    assert!(
        read_is_deleted(app, target_id).await,
        "target user MUST be soft-deleted"
    );
}

/// Delete without a TOTP code MUST be rejected with the missing-code error,
/// and the target user MUST remain undeleted.
#[tokio::test]
#[serial]
async fn test_delete_user_without_totp_rejected() {
    let app = TestApp::spawn().await;
    let (_op_id, op_uuid, op_name, _secret) = create_admin_with_mfa(app, "del_missing_op").await;

    let mut conn = app.get_conn().await;
    let target_id = create_simple_user(&mut conn, "del_missing_target").await;
    let target_uuid = get_user_uuid(&mut conn, target_id).await;

    let token = app
        .generate_test_token(&op_uuid.to_string(), &op_name, true, true)
        .await;
    let csrf = app.generate_csrf_token();
    drop(conn);

    let response = post_delete_user(app, target_uuid, &token, &csrf, None).await;
    assert_eq!(
        response
            .headers()
            .get(LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some(format!("/accounts/users/{}", target_uuid).as_str()),
        "missing step-up on delete must bounce to the detail page"
    );
    assert!(
        !read_is_deleted(app, target_id).await,
        "target MUST NOT be deleted when step-up is missing"
    );

    let flash = extract_flash_cookie(&response).expect("error flash expected");
    let detail = app
        .server
        .get(&format!("/accounts/users/{}", target_uuid))
        .add_header(COOKIE, format!("access_token={}; {}", token, flash))
        .await;
    let body = detail.text();
    assert!(
        body.contains("Please enter your authenticator code"),
        "delete UI must surface the explicit missing-code error, got: {}",
        &body[..body.len().min(800)]
    );
}

/// Delete with a wrong TOTP code MUST be rejected.
#[tokio::test]
#[serial]
async fn test_delete_user_with_wrong_totp_rejected() {
    let app = TestApp::spawn().await;
    let (_op_id, op_uuid, op_name, _secret) = create_admin_with_mfa(app, "del_wrong_op").await;

    let mut conn = app.get_conn().await;
    let target_id = create_simple_user(&mut conn, "del_wrong_target").await;
    let target_uuid = get_user_uuid(&mut conn, target_id).await;

    let token = app
        .generate_test_token(&op_uuid.to_string(), &op_name, true, true)
        .await;
    let csrf = app.generate_csrf_token();
    drop(conn);

    let response = post_delete_user(app, target_uuid, &token, &csrf, Some("000000")).await;
    assert_eq!(
        response
            .headers()
            .get(LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some(format!("/accounts/users/{}", target_uuid).as_str()),
    );
    assert!(
        !read_is_deleted(app, target_id).await,
        "target MUST NOT be deleted when step-up TOTP is wrong"
    );
}

/// An operator without enrolled MFA MUST NOT be able to delete users either.
/// This guarantees the step-up gate is uniform across all sensitive ops.
#[tokio::test]
#[serial]
async fn test_delete_user_operator_without_mfa_rejected() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("del_no_mfa_op");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let target_id = create_simple_user(&mut conn, "del_no_mfa_target").await;
    let target_uuid = get_user_uuid(&mut conn, target_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let csrf = app.generate_csrf_token();
    drop(conn);

    let response = post_delete_user(app, target_uuid, &token, &csrf, Some("123456")).await;
    assert_eq!(
        response
            .headers()
            .get(LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some(format!("/accounts/users/{}", target_uuid).as_str()),
    );
    assert!(
        !read_is_deleted(app, target_id).await,
        "target MUST NOT be deleted when operator has no MFA enrolled"
    );

    let flash = extract_flash_cookie(&response).expect("error flash expected");
    let detail = app
        .server
        .get(&format!("/accounts/users/{}", target_uuid))
        .add_header(COOKIE, format!("access_token={}; {}", token, flash))
        .await;
    let body = detail.text();
    assert!(
        body.contains("MFA enrollment required"),
        "operator without MFA must see the explicit refusal on delete too, got: {}",
        &body[..body.len().min(800)]
    );

    // Silence unused warning -- consumed via reset in other tests.
    let _ = reset_totp_replay_state;
}

// =============================================================================
// Issue #11 bug fix regression: encrypted MFA secret + missing vault client
// =============================================================================

/// Create an admin (is_staff + is_superuser) whose `mfa_secret` is a plausible
/// vauban-vault ciphertext envelope (`v1:<base64>`). This is what production
/// stores once an operator enrols MFA through the vault-backed flow.
///
/// In tests `app.state.vault_client` is `None` (see `tests/common/mod.rs`),
/// so this fixture deliberately puts the system in the *exact* configuration
/// that triggered issue #11: encrypted secret in DB + no vault to verify it.
async fn create_admin_with_encrypted_mfa(app: &TestApp, label: &str) -> (i32, Uuid, String) {
    let username = unique_name(label);
    let user_uuid = Uuid::new_v4();
    let hash = unwrap_ok!(app.auth_service.hash_password("StableAdminPwd#2026!"));
    // A realistic vault envelope shape -- prefix `v{digits}:` is what
    // `is_encrypted_mfa_secret` keys off of. The body is opaque to the web
    // process; only `vauban-vault` could decrypt it.
    let encrypted_secret = "v1:dGVzdC1lbmNyeXB0ZWQtbWZhLXNlY3JldC12YXVsdC1lbnZlbG9wZQ==";

    let do_insert = || {
        let username = username.clone();
        let hash = hash.clone();
        async move {
            let mut conn = app.get_conn().await;
            diesel::insert_into(users::table)
                .values((
                    users::uuid.eq(user_uuid),
                    users::username.eq(&username),
                    users::email.eq(format!("{}@test.local", username)),
                    users::password_hash.eq(&hash),
                    users::is_active.eq(true),
                    users::is_staff.eq(true),
                    users::is_superuser.eq(true),
                    users::mfa_enabled.eq(true),
                    users::mfa_secret.eq(Some(encrypted_secret)),
                    users::auth_source.eq(AuthSource::Local),
                    users::preferences.eq(serde_json::json!({})),
                ))
                .returning(users::id)
                .get_result::<i32>(&mut conn)
                .await
        }
    };
    let user_id: i32 = match do_insert().await {
        Ok(id) => id,
        Err(_) => unwrap_ok!(do_insert().await),
    };
    (user_id, user_uuid, username)
}

/// Issue #11 bugfix regression: when an operator's `mfa_secret` is a vault
/// envelope (`v1:...`) but `state.vault_client` is `None`, the password
/// rotation MUST surface the explicit "MFA backend is temporarily unavailable"
/// message and MUST NOT fail closed as a generic "Authenticator code is
/// incorrect" -- which would loop the operator forever (as reported by the
/// user: "je n'arrive plus à changer mon mot de passe, j'ai tout le temps un
/// 'Authenticator code is incorrect.'").
///
/// Before the fix, `AuthService::verify_totp` was called directly on the
/// ciphertext -- it silently returned `false` (the ciphertext is not valid
/// base32) and the handler reported `CodeInvalid`. After the fix, the
/// dispatch in `enforce_totp_step_up` detects the envelope via
/// `is_encrypted_mfa_secret` and returns `StepUpError::VaultUnavailable`
/// when the vault client is missing.
#[tokio::test]
#[serial]
async fn test_issue_11_encrypted_secret_without_vault_returns_explicit_error() {
    let app = TestApp::spawn().await;
    let (_op_id, op_uuid, op_name) =
        create_admin_with_encrypted_mfa(app, "issue11_enc_no_vault").await;

    let mut conn = app.get_conn().await;
    let target_id = create_simple_user(&mut conn, "issue11_enc_target").await;
    let target_uuid = get_user_uuid(&mut conn, target_id).await;
    let target_username = get_username(&mut conn, target_id).await;
    let target_email = get_email(&mut conn, target_id).await;
    let hash_before = get_password_hash(&mut conn, target_id).await;

    let token = app
        .generate_test_token(&op_uuid.to_string(), &op_name, true, true)
        .await;
    let csrf = app.generate_csrf_token();
    drop(conn);

    // Submit ANY 6-digit code -- the dispatch must short-circuit on the
    // missing vault BEFORE attempting to compare the code, so the value of
    // the code itself is irrelevant for this assertion.
    let response = post_edit_user_form(
        app,
        target_uuid,
        &token,
        &csrf,
        EditForm {
            username: &target_username,
            email: &target_email,
            password: Some("ShouldNotApplyPwd#2026"),
            totp_code: Some("123456"),
            is_active: true,
            ..Default::default()
        },
    )
    .await;

    assert_eq!(
        response
            .headers()
            .get(LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some(format!("/accounts/users/{}/edit", target_uuid).as_str()),
        "encrypted-secret + vault=None must bounce to the edit form"
    );

    let hash_after = read_hash(app, target_id).await;
    assert_eq!(
        hash_after, hash_before,
        "password MUST NOT be rotated when the vault is unavailable"
    );

    let flash = extract_flash_cookie(&response).expect("error flash expected");
    let edit = app
        .server
        .get(&format!("/accounts/users/{}/edit", target_uuid))
        .add_header(COOKIE, format!("access_token={}; {}", token, flash))
        .await;
    let body = edit.text();

    // The KEY assertion: the user-visible message must be the explicit
    // vault-unavailable copy, NOT the generic "code is incorrect" one. The
    // latter wording is what shipped the regression to production -- if it
    // ever reappears here we've reintroduced the bug.
    assert!(
        body.contains("MFA backend is temporarily unavailable"),
        "expected the explicit vault-unavailable error so operators stop \
         being told their (correct) code is wrong, got: {}",
        &body[..body.len().min(800)]
    );
    assert!(
        !body.contains("Authenticator code is incorrect"),
        "REGRESSION: operator with encrypted secret + no vault was told \
         their code is wrong instead of being told the backend is down. \
         Body: {}",
        &body[..body.len().min(800)]
    );
}

/// Same regression as above but on the user deletion path: deleting a user
/// with an encrypted operator secret + missing vault MUST refuse the
/// deletion AND surface the explicit vault-unavailable message. This guards
/// the parity between update_user_web and delete_user_web that
/// `enforce_totp_step_up` is supposed to provide.
#[tokio::test]
#[serial]
async fn test_issue_11_delete_user_encrypted_secret_without_vault_explicit_error() {
    let app = TestApp::spawn().await;
    let (_op_id, op_uuid, op_name) =
        create_admin_with_encrypted_mfa(app, "issue11_enc_del_no_vault").await;

    let mut conn = app.get_conn().await;
    let target_id = create_simple_user(&mut conn, "issue11_enc_del_target").await;
    let target_uuid = get_user_uuid(&mut conn, target_id).await;

    let token = app
        .generate_test_token(&op_uuid.to_string(), &op_name, true, true)
        .await;
    let csrf = app.generate_csrf_token();
    drop(conn);

    let response = post_delete_user(app, target_uuid, &token, &csrf, Some("123456")).await;

    assert_eq!(
        response
            .headers()
            .get(LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some(format!("/accounts/users/{}", target_uuid).as_str()),
        "encrypted-secret + vault=None must bounce to the detail page"
    );
    assert!(
        !read_is_deleted(app, target_id).await,
        "target MUST NOT be deleted when the vault is unavailable"
    );

    let flash = extract_flash_cookie(&response).expect("error flash expected");
    let detail = app
        .server
        .get(&format!("/accounts/users/{}", target_uuid))
        .add_header(COOKIE, format!("access_token={}; {}", token, flash))
        .await;
    let body = detail.text();
    assert!(
        body.contains("MFA backend is temporarily unavailable"),
        "delete UI must surface the explicit vault-unavailable error too, got: {}",
        &body[..body.len().min(800)]
    );
}
