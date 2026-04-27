/// VAUBAN Web - Integration tests for the self-service "Change Password"
/// modal opened from `/accounts/profile`.
///
/// **Background.** The rotation flow used to be a dead link to a non-existent
/// `/accounts/password/change` page. It is now an inline Alpine.js modal on
/// `/accounts/profile` posting to `POST /accounts/profile/password`. The
/// security model is the same step-up TOTP gate already enforced on the
/// admin Edit User page (issue #11): the operator's own current TOTP code
/// is the proof of identity, with no current-password fallback. The proof
/// is single-use within its 30-second window (RFC 6238 §5.2 replay
/// protection persisted via `users.last_totp_used_window`).
///
/// Test matrix (battle-tested):
/// - happy path (fresh TOTP, new == confirm, len >= min)        -> hash rotated, success flash
/// - reused TOTP (same code, same window, two calls)            -> second call rejected as replay
/// - missing/empty TOTP code                                    -> rejected, hash unchanged
/// - wrong TOTP code                                            -> rejected, hash unchanged
/// - new_password != confirm_password                           -> rejected, hash unchanged
/// - new_password shorter than `password_min_length`            -> rejected, hash unchanged
/// - operator has mfa_enabled=false                             -> rejected with "MFA enrollment required"
/// - operator's auth_source is LDAP/SAML                        -> rejected (federated identity)
/// - invalid CSRF token                                         -> rejected, hash unchanged
/// - GET /accounts/profile/password                             -> 405/404/redirect (no GET handler on purpose)
///
/// Template-side guards:
/// - profile.html with mfa_enabled renders the modal trigger button + form
/// - profile.html without mfa_enabled renders the MFA-required banner
///   (and NOT the modal) so a user with MFA disabled cannot even try to
///   submit the form
/// - profile.html for a federated user does NOT render either, only the
///   "managed by IDP" message
use crate::common::{TestApp, unwrap_ok, unwrap_some};
use crate::fixtures::unique_name;
use axum::http::header::{COOKIE, LOCATION, SET_COOKIE};
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serial_test::serial;
use uuid::Uuid;
use vauban_web::models::user::AuthSource;
use vauban_web::schema::users;
use vauban_web::services::auth::AuthService;

// =============================================================================
// Helpers
// =============================================================================

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

/// Read the current password hash via a freshly-acquired pooled connection
/// that is released as soon as the read completes. Mirrors the helper in
/// `user_edit_test.rs`: holding a pool slot across the POST + follow-up GET
/// has been observed to deadlock the test server's middleware stack under
/// parallel test execution.
async fn read_hash(app: &TestApp, user_id: i32) -> String {
    let mut conn = app.get_conn().await;
    get_password_hash(&mut conn, user_id).await
}

/// Extract the signed `__vauban_flash` cookie from a response so it can be
/// replayed on the follow-up GET.
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

/// Compute the TOTP code that the handler would accept *right now* for the
/// given base32-encoded shared secret.
fn current_totp_code(secret: &str) -> String {
    unwrap_some!(AuthService::get_current_totp(secret))
}

/// Reset `last_totp_used_window` to NULL so a test can produce two distinct
/// successful step-ups inside the same Tokio runtime tick. Matches the
/// helper in `user_edit_test.rs`.
async fn reset_totp_replay_state(app: &TestApp, user_id: i32) {
    let mut conn = app.get_conn().await;
    unwrap_ok!(
        diesel::update(users::table.filter(users::id.eq(user_id)))
            .set(users::last_totp_used_window.eq::<Option<i64>>(None))
            .execute(&mut conn)
            .await
    );
}

/// Create a local-auth operator with a freshly-enrolled TOTP factor and a
/// stable Argon2 password hash. Returns `(user_id, uuid, username, secret)`.
///
/// The password hash is real Argon2 (not a placeholder string) so any code
/// path that accidentally tries to verify it against a candidate cannot
/// short-circuit on a malformed PHC string.
async fn create_local_user_with_mfa(
    app: &TestApp,
    label: &str,
    is_staff: bool,
    is_superuser: bool,
) -> (i32, Uuid, String, String) {
    let username = unique_name(label);
    let user_uuid = Uuid::new_v4();
    let hash = unwrap_ok!(app.auth_service.hash_password("StableInitialPwd#2026!"));
    let (mfa_secret, _provisioning_uri) =
        unwrap_ok!(AuthService::generate_totp_secret(&username, "VAUBAN-tests"));

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
                    users::is_staff.eq(is_staff),
                    users::is_superuser.eq(is_superuser),
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

/// Create a local-auth operator WITHOUT a TOTP factor enrolled. Mirrors
/// [`create_local_user_with_mfa`] otherwise.
async fn create_local_user_without_mfa(app: &TestApp, label: &str) -> (i32, Uuid, String) {
    let username = unique_name(label);
    let user_uuid = Uuid::new_v4();
    let hash = unwrap_ok!(app.auth_service.hash_password("StableInitialPwd#2026!"));

    let mut conn = app.get_conn().await;
    let user_id: i32 = unwrap_ok!(
        diesel::insert_into(users::table)
            .values((
                users::uuid.eq(user_uuid),
                users::username.eq(&username),
                users::email.eq(format!("{}@test.local", username)),
                users::password_hash.eq(&hash),
                users::is_active.eq(true),
                users::is_staff.eq(false),
                users::is_superuser.eq(false),
                users::mfa_enabled.eq(false),
                users::mfa_secret.eq::<Option<String>>(None),
                users::auth_source.eq(AuthSource::Local),
                users::preferences.eq(serde_json::json!({})),
            ))
            .returning(users::id)
            .get_result::<i32>(&mut conn)
            .await
    );
    (user_id, user_uuid, username)
}

/// Create a federated (LDAP) operator WITH MFA enrolled. Used to assert
/// that the password rotation refuses non-local accounts even when their
/// TOTP step-up would otherwise succeed.
async fn create_ldap_user_with_mfa(app: &TestApp, label: &str) -> (i32, Uuid, String, String) {
    let username = unique_name(label);
    let user_uuid = Uuid::new_v4();
    let hash = unwrap_ok!(app.auth_service.hash_password("StableInitialPwd#2026!"));
    let (mfa_secret, _) = unwrap_ok!(AuthService::generate_totp_secret(&username, "VAUBAN-tests"));

    let mut conn = app.get_conn().await;
    let user_id: i32 = unwrap_ok!(
        diesel::insert_into(users::table)
            .values((
                users::uuid.eq(user_uuid),
                users::username.eq(&username),
                users::email.eq(format!("{}@test.local", username)),
                users::password_hash.eq(&hash),
                users::is_active.eq(true),
                users::is_staff.eq(false),
                users::is_superuser.eq(false),
                users::mfa_enabled.eq(true),
                users::mfa_secret.eq(Some(&mfa_secret)),
                users::auth_source.eq(AuthSource::Ldap),
                users::preferences.eq(serde_json::json!({})),
            ))
            .returning(users::id)
            .get_result::<i32>(&mut conn)
            .await
    );
    (user_id, user_uuid, username, mfa_secret)
}

/// Form payload for the change-password POST.
#[derive(Default)]
struct PwForm<'a> {
    new_password: &'a str,
    confirm_password: &'a str,
    totp_code: &'a str,
}

/// POST /accounts/profile/password as `token`. The CSRF cookie is set in the
/// `Cookie` header so the double-submit check passes.
async fn post_change_password(
    app: &TestApp,
    token: &str,
    csrf: &str,
    f: PwForm<'_>,
) -> axum_test::TestResponse {
    app.server
        .post("/accounts/profile/password")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf),
        )
        .form(&[
            ("csrf_token", csrf),
            ("new_password", f.new_password),
            ("confirm_password", f.confirm_password),
            ("totp_code", f.totp_code),
        ])
        .await
}

/// POST /accounts/profile/password with a deliberately wrong CSRF token in
/// the form body (cookie still valid). Used for the CSRF rejection path.
async fn post_change_password_bad_csrf(
    app: &TestApp,
    token: &str,
    cookie_csrf: &str,
    body_csrf: &str,
    f: PwForm<'_>,
) -> axum_test::TestResponse {
    app.server
        .post("/accounts/profile/password")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, cookie_csrf),
        )
        .form(&[
            ("csrf_token", body_csrf),
            ("new_password", f.new_password),
            ("confirm_password", f.confirm_password),
            ("totp_code", f.totp_code),
        ])
        .await
}

/// Assert that `response` is a PRG redirect (302/303) to `/accounts/profile`,
/// which is the canonical landing page for every outcome of the modal
/// (success or failure). Returns the flash cookie for follow-up GET.
fn assert_redirect_to_profile(response: &axum_test::TestResponse) -> String {
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
        .unwrap_or_default();
    assert_eq!(
        location, "/accounts/profile",
        "every change-password outcome MUST redirect back to /accounts/profile, got '{}'",
        location
    );
    extract_flash_cookie(response).expect("flash cookie must be set on every PRG outcome")
}

/// Fetch /accounts/profile with a flash cookie attached and return the
/// response body. Used to assert the flash banner the user actually sees.
async fn fetch_profile_with_flash(app: &TestApp, token: &str, flash_cookie: &str) -> String {
    let response = app
        .server
        .get("/accounts/profile")
        .add_header(COOKIE, format!("access_token={}; {}", token, flash_cookie))
        .await;
    assert_eq!(
        response.status_code().as_u16(),
        200,
        "follow-up GET /accounts/profile must succeed"
    );
    response.text()
}

// =============================================================================
// Happy path
// =============================================================================

/// Submitting matching new+confirm passwords with a fresh TOTP code MUST
/// rotate the password hash to a new Argon2id digest, redirect to
/// /accounts/profile, and surface a "Password updated successfully" banner
/// on the next page load.
#[tokio::test]
#[serial]
async fn test_change_password_happy_path_rotates_hash_and_flashes_success() {
    let app = TestApp::spawn().await;
    let (user_id, user_uuid, username, mfa_secret) =
        create_local_user_with_mfa(app, "cp_happy", false, false).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;
    let csrf = app.generate_csrf_token();

    let hash_before = read_hash(app, user_id).await;
    let totp = current_totp_code(&mfa_secret);

    let response = post_change_password(
        app,
        &token,
        &csrf,
        PwForm {
            new_password: "BrandNewSelfRotation#2026",
            confirm_password: "BrandNewSelfRotation#2026",
            totp_code: &totp,
        },
    )
    .await;

    let flash = assert_redirect_to_profile(&response);
    let hash_after = read_hash(app, user_id).await;
    assert_ne!(
        hash_after, hash_before,
        "happy path MUST rotate the user's password hash"
    );
    assert!(
        hash_after.starts_with("$argon2"),
        "rotated hash MUST be an Argon2 PHC string, got prefix '{}'",
        &hash_after[..hash_after.len().min(20)]
    );

    let body = fetch_profile_with_flash(app, &token, &flash).await;
    assert!(
        body.contains("Password updated successfully"),
        "profile page MUST surface the success banner; got: {}",
        &body[..body.len().min(800)]
    );
    assert!(
        body.contains("bg-green-50"),
        "success banner must use the green Tailwind style"
    );
}

// =============================================================================
// Step-up TOTP failure modes
// =============================================================================

/// RFC 6238 §5.2 replay protection: once a code has been consumed by a
/// successful rotation, the SAME code MUST be refused on the next attempt
/// even within the same 30-second window.
#[tokio::test]
#[serial]
async fn test_change_password_replay_attack_rejected() {
    let app = TestApp::spawn().await;
    let (user_id, user_uuid, username, mfa_secret) =
        create_local_user_with_mfa(app, "cp_replay", false, false).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;
    let csrf = app.generate_csrf_token();
    let totp = current_totp_code(&mfa_secret);

    let r1 = post_change_password(
        app,
        &token,
        &csrf,
        PwForm {
            new_password: "FirstRotation#2026",
            confirm_password: "FirstRotation#2026",
            totp_code: &totp,
        },
    )
    .await;
    let _ = assert_redirect_to_profile(&r1);
    let hash_after_first = read_hash(app, user_id).await;

    // Same code, second attempt.
    let r2 = post_change_password(
        app,
        &token,
        &csrf,
        PwForm {
            new_password: "ReplayedRotation#2026",
            confirm_password: "ReplayedRotation#2026",
            totp_code: &totp,
        },
    )
    .await;
    let flash = assert_redirect_to_profile(&r2);
    let hash_after_second = read_hash(app, user_id).await;
    assert_eq!(
        hash_after_first, hash_after_second,
        "replayed TOTP code MUST NOT rotate the hash a second time"
    );

    let body = fetch_profile_with_flash(app, &token, &flash).await;
    assert!(
        body.contains("already been used"),
        "replay error wording must be explicit, got: {}",
        &body[..body.len().min(800)]
    );
}

/// Empty `totp_code` MUST be refused with the dedicated CodeMissing flash
/// (and NOT confused with "code invalid", which would imply we accepted the
/// empty string as a candidate).
#[tokio::test]
#[serial]
async fn test_change_password_empty_totp_code_rejected() {
    let app = TestApp::spawn().await;
    let (user_id, user_uuid, username, _secret) =
        create_local_user_with_mfa(app, "cp_empty_totp", false, false).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;
    let csrf = app.generate_csrf_token();
    let hash_before = read_hash(app, user_id).await;

    let response = post_change_password(
        app,
        &token,
        &csrf,
        PwForm {
            new_password: "NewSelfRotation#2026",
            confirm_password: "NewSelfRotation#2026",
            totp_code: "",
        },
    )
    .await;
    let flash = assert_redirect_to_profile(&response);

    let hash_after = read_hash(app, user_id).await;
    assert_eq!(hash_after, hash_before, "missing totp MUST NOT rotate hash");

    let body = fetch_profile_with_flash(app, &token, &flash).await;
    assert!(
        body.contains("Please enter your authenticator code"),
        "empty totp must trigger the CodeMissing flash, got: {}",
        &body[..body.len().min(800)]
    );
}

/// Wrong TOTP code MUST be refused with "Authenticator code is incorrect."
/// and the hash MUST stay unchanged.
#[tokio::test]
#[serial]
async fn test_change_password_wrong_totp_code_rejected() {
    let app = TestApp::spawn().await;
    let (user_id, user_uuid, username, _secret) =
        create_local_user_with_mfa(app, "cp_wrong_totp", false, false).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;
    let csrf = app.generate_csrf_token();
    let hash_before = read_hash(app, user_id).await;

    let response = post_change_password(
        app,
        &token,
        &csrf,
        PwForm {
            new_password: "AnotherSelfRotation#2026",
            confirm_password: "AnotherSelfRotation#2026",
            totp_code: "000000",
        },
    )
    .await;
    let flash = assert_redirect_to_profile(&response);

    let hash_after = read_hash(app, user_id).await;
    assert_eq!(hash_after, hash_before, "wrong totp MUST NOT rotate hash");

    let body = fetch_profile_with_flash(app, &token, &flash).await;
    assert!(
        body.contains("Authenticator code is incorrect"),
        "wrong totp must trigger the CodeInvalid flash, got: {}",
        &body[..body.len().min(800)]
    );
}

/// Operator with `mfa_enabled = false` MUST be refused with the explicit
/// MFA-enrollment-required flash. This makes the failure recoverable: the
/// flash steers the user to /accounts/mfa/setup instead of leaving them to
/// guess why their submission was rejected.
#[tokio::test]
#[serial]
async fn test_change_password_refuses_when_mfa_not_enrolled() {
    let app = TestApp::spawn().await;
    let (user_id, user_uuid, username) = create_local_user_without_mfa(app, "cp_no_mfa").await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;
    let csrf = app.generate_csrf_token();
    let hash_before = read_hash(app, user_id).await;

    // Even with a syntactically valid 6-digit code, the operator's lack of
    // an enrolled secret must short-circuit the step-up.
    let response = post_change_password(
        app,
        &token,
        &csrf,
        PwForm {
            new_password: "PointlessRotation#2026",
            confirm_password: "PointlessRotation#2026",
            totp_code: "123456",
        },
    )
    .await;
    let flash = assert_redirect_to_profile(&response);

    let hash_after = read_hash(app, user_id).await;
    assert_eq!(
        hash_after, hash_before,
        "user without MFA MUST NOT be allowed to rotate their password"
    );

    let body = fetch_profile_with_flash(app, &token, &flash).await;
    assert!(
        body.contains("MFA enrollment required"),
        "missing MFA must trigger the MfaNotEnrolled flash, got: {}",
        &body[..body.len().min(800)]
    );
}

// =============================================================================
// Form-input failure modes
// =============================================================================

/// new_password != confirm_password MUST be refused before any DB lookup or
/// vault round-trip; this is purely a user-input mistake.
#[tokio::test]
#[serial]
async fn test_change_password_mismatched_confirm_rejected() {
    let app = TestApp::spawn().await;
    let (user_id, user_uuid, username, mfa_secret) =
        create_local_user_with_mfa(app, "cp_mismatch", false, false).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;
    let csrf = app.generate_csrf_token();
    let hash_before = read_hash(app, user_id).await;
    let totp = current_totp_code(&mfa_secret);

    let response = post_change_password(
        app,
        &token,
        &csrf,
        PwForm {
            new_password: "OneSecretValue#2026",
            confirm_password: "ANOTHER_one#2026!!",
            totp_code: &totp,
        },
    )
    .await;
    let flash = assert_redirect_to_profile(&response);

    let hash_after = read_hash(app, user_id).await;
    assert_eq!(
        hash_after, hash_before,
        "mismatched confirm MUST NOT rotate hash"
    );

    let body = fetch_profile_with_flash(app, &token, &flash).await;
    assert!(
        body.contains("New password and confirmation do not match"),
        "mismatched confirm must trigger the dedicated flash, got: {}",
        &body[..body.len().min(800)]
    );

    // Critical: because the mismatch check runs BEFORE the step-up, the
    // TOTP code must NOT have been consumed -- a follow-up correct
    // submission with the same code (in the same window) MUST still
    // succeed. Otherwise users would be locked out for ~30s every time
    // they fat-finger the confirm field.
    reset_totp_replay_state(app, user_id).await; // belt-and-braces
    let totp2 = current_totp_code(&mfa_secret);
    let r2 = post_change_password(
        app,
        &token,
        &csrf,
        PwForm {
            new_password: "FollowUpOK#2026!!",
            confirm_password: "FollowUpOK#2026!!",
            totp_code: &totp2,
        },
    )
    .await;
    let _ = assert_redirect_to_profile(&r2);
    let hash_after2 = read_hash(app, user_id).await;
    assert_ne!(
        hash_after2, hash_before,
        "post-typo retry with valid form must succeed"
    );
}

/// new_password shorter than `password_min_length` MUST be refused with the
/// explicit "Password must be at least N characters" flash. Same length
/// policy as create_user_web / update_user_web.
#[tokio::test]
#[serial]
async fn test_change_password_too_short_rejected() {
    let app = TestApp::spawn().await;
    let (user_id, user_uuid, username, mfa_secret) =
        create_local_user_with_mfa(app, "cp_short", false, false).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;
    let csrf = app.generate_csrf_token();
    let hash_before = read_hash(app, user_id).await;
    let totp = current_totp_code(&mfa_secret);

    let response = post_change_password(
        app,
        &token,
        &csrf,
        PwForm {
            new_password: "abc",
            confirm_password: "abc",
            totp_code: &totp,
        },
    )
    .await;
    let flash = assert_redirect_to_profile(&response);

    let hash_after = read_hash(app, user_id).await;
    assert_eq!(
        hash_after, hash_before,
        "short password MUST NOT rotate hash"
    );

    let body = fetch_profile_with_flash(app, &token, &flash).await;
    assert!(
        body.contains("Password must be at least"),
        "short password must trigger the length flash, got: {}",
        &body[..body.len().min(800)]
    );
}

// =============================================================================
// Federated identities
// =============================================================================

/// LDAP/SAML/OIDC users own their password in the upstream IdP. Rotating
/// only the local hash would silently desynchronise the two and lock the
/// user out of SSO. The handler MUST refuse with an actionable flash.
#[tokio::test]
#[serial]
async fn test_change_password_refuses_federated_account() {
    let app = TestApp::spawn().await;
    let (user_id, user_uuid, username, mfa_secret) =
        create_ldap_user_with_mfa(app, "cp_ldap").await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;
    let csrf = app.generate_csrf_token();
    let hash_before = read_hash(app, user_id).await;
    let totp = current_totp_code(&mfa_secret);

    let response = post_change_password(
        app,
        &token,
        &csrf,
        PwForm {
            new_password: "LdapAttempt#2026!!",
            confirm_password: "LdapAttempt#2026!!",
            totp_code: &totp,
        },
    )
    .await;
    let flash = assert_redirect_to_profile(&response);

    let hash_after = read_hash(app, user_id).await;
    assert_eq!(
        hash_after, hash_before,
        "federated user MUST NOT rotate their local hash"
    );

    let body = fetch_profile_with_flash(app, &token, &flash).await;
    assert!(
        body.contains("managed by your identity provider"),
        "federated user must see the IDP-ownership flash, got: {}",
        &body[..body.len().min(800)]
    );
}

// =============================================================================
// CSRF
// =============================================================================

/// A POST whose body's `csrf_token` does NOT match the cookie's CSRF token
/// MUST be refused, hash unchanged. Mirrors the CSRF gate on every other
/// state-mutating handler in the module.
#[tokio::test]
#[serial]
async fn test_change_password_invalid_csrf_rejected() {
    let app = TestApp::spawn().await;
    let (user_id, user_uuid, username, mfa_secret) =
        create_local_user_with_mfa(app, "cp_csrf", false, false).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;
    let cookie_csrf = app.generate_csrf_token();
    let body_csrf = "totally-bogus-csrf-token";
    let hash_before = read_hash(app, user_id).await;
    let totp = current_totp_code(&mfa_secret);

    let response = post_change_password_bad_csrf(
        app,
        &token,
        &cookie_csrf,
        body_csrf,
        PwForm {
            new_password: "ShouldNotRotate#2026!!",
            confirm_password: "ShouldNotRotate#2026!!",
            totp_code: &totp,
        },
    )
    .await;
    let flash = assert_redirect_to_profile(&response);

    let hash_after = read_hash(app, user_id).await;
    assert_eq!(hash_after, hash_before, "bad CSRF MUST NOT rotate hash");

    let body = fetch_profile_with_flash(app, &token, &flash).await;
    assert!(
        body.contains("Invalid CSRF token"),
        "bad CSRF must trigger the CSRF flash, got: {}",
        &body[..body.len().min(800)]
    );
}

// =============================================================================
// Method/handler shape
// =============================================================================

/// There is NO GET /accounts/profile/password handler on purpose: the form
/// is rendered inline by the profile template's modal. A direct GET MUST
/// therefore not return a 200 OK -- otherwise stray bookmarks would land on
/// a phantom page that has no route. Accept any of: 404, 405, or a redirect
/// (the fallback handler may map unknowns to /).
#[tokio::test]
#[serial]
async fn test_change_password_get_is_not_allowed() {
    let app = TestApp::spawn().await;
    let (_id, user_uuid, username, _secret) =
        create_local_user_with_mfa(app, "cp_no_get", false, false).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;

    let response = app
        .server
        .get("/accounts/profile/password")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status != 200,
        "GET /accounts/profile/password MUST NOT return 200 (form is inline on profile), got {}",
        status
    );
}

// =============================================================================
// Profile page rendering
// =============================================================================

/// The profile page for an MFA-enrolled local user MUST render the modal
/// trigger button with the dedicated `data-testid` so QA / e2e tests can
/// reliably target it, AND must NOT render the MFA-required banner.
#[tokio::test]
#[serial]
async fn test_profile_page_renders_change_password_modal_for_mfa_local_user() {
    let app = TestApp::spawn().await;
    let (_id, user_uuid, username, _secret) =
        create_local_user_with_mfa(app, "cp_render_local", false, false).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;

    let response = app
        .server
        .get("/accounts/profile")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_eq!(response.status_code().as_u16(), 200);

    let body = response.text();
    assert!(
        body.contains(r#"data-testid="change-password-trigger""#),
        "MFA-enrolled local user MUST see the change-password trigger button"
    );
    assert!(
        body.contains(r#"action="/accounts/profile/password""#),
        "modal MUST contain the form posting to /accounts/profile/password"
    );
    assert!(
        !body.contains(r#"data-testid="change-password-mfa-required""#),
        "MFA-enrolled user MUST NOT see the MFA-required banner"
    );
    assert!(
        !body.contains("/accounts/password/change"),
        "the dead link to /accounts/password/change MUST be gone"
    );
}

/// The profile page for a local user WITHOUT MFA MUST render the
/// MFA-required banner pointing at /accounts/mfa, and MUST NOT render the
/// modal (so the user cannot even attempt to submit).
#[tokio::test]
#[serial]
async fn test_profile_page_renders_mfa_required_banner_when_mfa_absent() {
    let app = TestApp::spawn().await;
    let (_id, user_uuid, username) = create_local_user_without_mfa(app, "cp_render_no_mfa").await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;

    let response = app
        .server
        .get("/accounts/profile")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_eq!(response.status_code().as_u16(), 200);

    let body = response.text();
    assert!(
        body.contains(r#"data-testid="change-password-mfa-required""#),
        "local user without MFA MUST see the MFA-required banner"
    );
    assert!(
        !body.contains(r#"data-testid="change-password-trigger""#),
        "local user without MFA MUST NOT see the change-password trigger"
    );
    assert!(
        body.contains("/accounts/mfa"),
        "MFA banner MUST link to /accounts/mfa"
    );
}

/// The profile page for a federated (LDAP) user MUST render neither the
/// modal trigger nor the MFA-required banner, only the "managed by IDP"
/// message. That keeps the UI honest about who actually owns the
/// credential.
#[tokio::test]
#[serial]
async fn test_profile_page_does_not_render_modal_for_federated_user() {
    let app = TestApp::spawn().await;
    let (_id, user_uuid, username, _secret) =
        create_ldap_user_with_mfa(app, "cp_render_ldap").await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;

    let response = app
        .server
        .get("/accounts/profile")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_eq!(response.status_code().as_u16(), 200);

    let body = response.text();
    assert!(
        !body.contains(r#"data-testid="change-password-trigger""#),
        "federated user MUST NOT see the change-password trigger"
    );
    assert!(
        !body.contains(r#"data-testid="change-password-mfa-required""#),
        "federated user MUST NOT see the MFA-required banner"
    );
    assert!(
        body.contains("Password is managed by"),
        "federated user MUST see the IDP-ownership message"
    );
}
