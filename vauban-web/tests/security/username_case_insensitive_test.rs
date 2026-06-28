//! End-to-end tests for case-insensitive login identifiers.
//!
//! Vauban canonicalises every username to its trimmed + lower-cased form
//! at every write site (`shared::username::normalize_username`) and looks
//! it up by the same canonical form, with a DB-level `lower(username)`
//! unique index as the final backstop. These tests pin the contract end
//! to end:
//!
//!  * a local account logs in regardless of the casing typed,
//!  * the API create path stores the canonical (lower-cased) identity,
//!  * the DB rejects a case-variant duplicate,
//!  * the LDAP just-in-time path never mints a second shadow row for a
//!    different-cased spelling of the same directory identity.

use axum::http::{HeaderName, header};
use serde_json::json;
use serial_test::serial;

use diesel::{ExpressionMethods, OptionalExtension, QueryDsl};
use diesel_async::AsyncPgConnection;
use diesel_async::RunQueryDsl as _;

use crate::common::auth_ipc_test_service::LDAP_GOOD_PASSWORD;
use crate::common::{TestApp, test_db, unwrap_ok};
use crate::fixtures::unique_name;
use vauban_web::models::user::{AuthSource, NewUser, User};
use vauban_web::schema::users;

/// A local password that satisfies both the login validator (>= 12) and
/// the creation complexity policy (upper + lower + digit + special).
const LOCAL_PASSWORD: &str = "CaseTest-Pass1!";

async fn insert_local_user(
    app: &TestApp,
    conn: &mut AsyncPgConnection,
    username: &str,
    password: &str,
) -> User {
    let password_hash = unwrap_ok!(app.auth_service.hash_password(password));
    let new_user = NewUser {
        uuid: ::uuid::Uuid::new_v4(),
        username: username.to_string(),
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
    unwrap_ok!(
        diesel::insert_into(users::table)
            .values(&new_user)
            .get_result(conn)
            .await
    )
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

async fn count_active_by_username(conn: &mut AsyncPgConnection, username: &str) -> i64 {
    users::table
        .filter(users::username.eq(username))
        .filter(users::is_deleted.eq(false))
        .count()
        .get_result(conn)
        .await
        .unwrap_or(-1)
}

/// A local account created with a lower-case username authenticates when
/// the operator types ANY casing of that identifier.
#[tokio::test]
#[serial]
async fn local_login_is_case_insensitive() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Stored canonical (lower-case) identity.
    let username = unique_name("test_ci_login");
    insert_local_user(app, &mut conn, &username, LOCAL_PASSWORD).await;

    // Every casing of the identifier must reach the same account and be
    // routed to MFA enrolment (the account has no MFA yet).
    for typed in [
        username.clone(),
        username.to_uppercase(),
        // Mixed case: capitalise the first letter only.
        {
            let mut c = username.chars();
            c.next()
                .map(|f| f.to_uppercase().collect::<String>() + c.as_str())
                .unwrap_or_default()
        },
        // Surrounding whitespace must be trimmed away too.
        format!("  {}  ", username.to_uppercase()),
    ] {
        let response = login_web_htmx(app, &typed, LOCAL_PASSWORD).await;
        assert_eq!(
            response.status_code().as_u16(),
            200,
            "login with {typed:?} should be accepted"
        );
        assert_eq!(
            hx_redirect(&response).as_deref(),
            Some("/mfa/setup"),
            "login with {typed:?} must resolve to the same account"
        );
    }

    // Control: a wrong password is still rejected regardless of casing.
    let bad = login_web_htmx(app, &username.to_uppercase(), "WrongPassword-9!").await;
    assert!(
        hx_redirect(&bad).is_none(),
        "wrong password must never authenticate"
    );

    test_db::cleanup(&mut conn).await;
}

/// The admin create form stores the canonical (lower-cased) identity, so
/// a mixed-case username typed at creation can subsequently log in by any
/// casing -- proving the write site and the lookup agree end to end.
#[tokio::test]
#[serial]
async fn web_create_user_stores_canonical_username() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Acting superuser (carries users:write). Web auth is cookie-based.
    let admin_uuid = ::uuid::Uuid::new_v4();
    let admin_name = unique_name("test_ci_admin");
    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let csrf = app.generate_csrf_token();

    // Canonical (lower-case) identity keeps the `test_` cleanup prefix;
    // the operator types it ALL-UPPER to exercise normalization.
    let expected = unique_name("test_ci_create");
    let typed_username = expected.to_uppercase();
    let password = "CreatePass-1!";

    let response = app
        .server
        .post("/accounts/users")
        .add_header(
            header::COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf),
        )
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("username", typed_username.as_str()),
            ("email", &format!("{}@test.vauban.io", expected)),
            ("password", password),
            ("is_active", "on"),
        ])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "create should redirect on success, got {status}: {}",
        response.text()
    );

    // The row exists under the canonical form, and NOT under the typed
    // mixed-case form.
    assert_eq!(
        count_active_by_username(&mut conn, &expected).await,
        1,
        "the canonical lower-cased username must be the stored identity"
    );
    assert_eq!(
        count_active_by_username(&mut conn, &typed_username).await,
        0,
        "the mixed-case spelling must not be a stored identity"
    );

    // End to end: the freshly created account logs in by ANY casing.
    let login = login_web_htmx(app, &typed_username, password).await;
    assert_eq!(hx_redirect(&login).as_deref(), Some("/mfa/setup"));
    let login_lower = login_web_htmx(app, &expected, password).await;
    assert_eq!(hx_redirect(&login_lower).as_deref(), Some("/mfa/setup"));

    // Both accounts carry the `test_` prefix, so the standard cleanup
    // (cascade-deleting sessions via the FK) is enough.
    test_db::cleanup(&mut conn).await;
}

/// The DB-level `lower(username)` unique index is the last line of
/// defence: inserting a case-variant of an existing identity must be
/// rejected even though the legacy column UNIQUE is case-sensitive.
#[tokio::test]
#[serial]
async fn db_unique_index_rejects_case_variant() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("test_ci_dup");
    insert_local_user(app, &mut conn, &username, LOCAL_PASSWORD).await;

    // Same identity, different casing, distinct uuid + email so the only
    // possible conflict is the case-insensitive username index.
    let variant = username.to_uppercase();
    let dup = NewUser {
        uuid: ::uuid::Uuid::new_v4(),
        username: variant.clone(),
        email: format!("{}-variant@test.vauban.io", username),
        password_hash: "x".to_string(),
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
    let result: Result<User, _> = diesel::insert_into(users::table)
        .values(&dup)
        .get_result(&mut conn)
        .await;
    assert!(
        result.is_err(),
        "inserting a case-variant of an existing username must violate the lower(username) unique index"
    );

    test_db::cleanup(&mut conn).await;
}

/// LDAP just-in-time provisioning must be case-insensitive: a second
/// login with a different casing of the same directory identity binds to
/// the already-provisioned row instead of minting a duplicate shadow
/// account (the latent pre-fix bug).
#[tokio::test]
#[serial]
async fn ldap_jit_does_not_duplicate_on_case_variant() {
    let app = TestApp::spawn_ldap().await;
    let mut conn = app.get_conn().await;

    let typed_first = format!("Test_LDAP_Case_{}", unique_name("x"));
    let canonical = typed_first.to_lowercase();

    // First login (mixed case) -> JIT provisions the canonical identity.
    let r1 = login_web_htmx(app, &typed_first, LDAP_GOOD_PASSWORD).await;
    assert_eq!(r1.status_code().as_u16(), 200);
    assert_eq!(hx_redirect(&r1).as_deref(), Some("/mfa/setup"));
    assert_eq!(
        count_active_by_username(&mut conn, &canonical).await,
        1,
        "first login must provision exactly one row"
    );

    // Second login with a DIFFERENT casing must reach the SAME row.
    let typed_second = typed_first.to_uppercase();
    let r2 = login_web_htmx(app, &typed_second, LDAP_GOOD_PASSWORD).await;
    assert_eq!(r2.status_code().as_u16(), 200);
    assert_eq!(
        hx_redirect(&r2).as_deref(),
        Some("/mfa/setup"),
        "second (re-cased) login must resolve to the existing account"
    );
    assert_eq!(
        count_active_by_username(&mut conn, &canonical).await,
        1,
        "a re-cased LDAP login must NOT mint a duplicate shadow account"
    );

    // Sanity: the provisioned account carries the canonical username and
    // preserves the originally-typed casing in external_id (forensics).
    let row: Option<User> = users::table
        .filter(users::username.eq(&canonical))
        .filter(users::is_deleted.eq(false))
        .first::<User>(&mut conn)
        .await
        .optional()
        .unwrap_or(None);
    let row = row.expect("JIT row must exist");
    assert_eq!(row.auth_source, AuthSource::Ldap);
    assert_eq!(row.external_id.as_deref(), Some(typed_first.as_str()));

    // The canonical username carries the `test_` prefix, so the standard
    // cleanup (cascade-deleting auth_sessions via the FK) is enough.
    test_db::cleanup(&mut conn).await;
}
