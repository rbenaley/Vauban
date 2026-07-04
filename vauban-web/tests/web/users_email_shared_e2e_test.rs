//! End-to-end coverage for the relaxed user e-mail model
//! (migration `20260704000000_users_email_drop_unique`).
//!
//! Before the migration, `users.email` carried a table-level UNIQUE
//! constraint, which made it impossible to give one person several
//! accounts (e.g. a nominal account plus an admin/break-glass account)
//! sharing the same address. The new contract:
//!
//! * **`email` is NOT unique** -- any number of ACTIVE accounts may
//!   carry the same address. It stays NOT NULL and format-validated.
//! * **`username` remains the sole identity key** -- unique
//!   case-insensitively (`idx_users_username_lower`) and the only
//!   identifier the login flow resolves, so shared e-mails can never
//!   make authentication ambiguous.
//!
//! Layered, per the house model (assets_name_uniqueness_e2e_test):
//! 1. full-stack web flows (create / edit-into-shared-address);
//! 2. DB-level invariants straight against the pg catalog and the
//!    INSERT path (no unique constraint/index left on email, username
//!    sentinel index still present);
//! 3. structural source pins (handlers no longer gate on duplicate
//!    e-mail, login never resolves users by e-mail, the migration
//!    drops the constraint by shape).

use crate::common::{TestApp, assertions::*, test_db, unwrap_ok};
use crate::fixtures::{create_admin_user, create_test_user, unique_name};
use axum::http::header::{COOKIE, LOCATION};
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::RunQueryDsl;
use serial_test::serial;
use vauban_web::schema::users;

const USERS_WEB_SRC: &str = include_str!("../../src/handlers/web/users.rs");
const AUTH_SRC: &str = include_str!("../../src/handlers/auth.rs");
const SUPERVISOR_ADMIN_SRC: &str = include_str!("../../../vauban-supervisor/src/admin.rs");
const MIGRATION_UP_SQL: &str =
    include_str!("../../../vauban-db/migrations/20260704000000_users_email_drop_unique/up.sql");
const MIGRATION_DOWN_SQL: &str =
    include_str!("../../../vauban-db/migrations/20260704000000_users_email_drop_unique/down.sql");

/// Cookie header carrying both auth and CSRF, as expected by the web
/// create/edit handlers (double-submit pattern).
fn auth_csrf_cookie(token: &str, csrf: &str) -> String {
    format!("access_token={}; __vauban_csrf={}", token, csrf)
}

/// Count ACTIVE users carrying `email`.
async fn active_holders(conn: &mut diesel_async::AsyncPgConnection, email: &str) -> i64 {
    unwrap_ok!(
        users::table
            .filter(users::email.eq(email))
            .filter(users::is_deleted.eq(false))
            .count()
            .get_result(conn)
            .await
    )
}

#[derive(diesel::QueryableByName)]
struct CountRow {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    n: i64,
}

// =============================================================================
// 1. Web create: two accounts for the same person, same e-mail
// =============================================================================

/// THE regression test for the client-reported limitation: creating two
/// accounts through the admin web form with the SAME e-mail address must
/// succeed for both, and both must land active in the database.
#[tokio::test]
#[serial]
async fn test_e2e_two_accounts_same_email_both_created() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(
        &mut conn,
        &app.auth_service,
        &unique_name("email_shared_adm"),
    )
    .await;
    let csrf = app.generate_csrf_token();

    let shared_email = format!("{}@shared.test", unique_name("person"));
    let usernames = [unique_name("nominal"), unique_name("breakglass")];

    for username in &usernames {
        let resp = app
            .server
            .post("/accounts/users")
            .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
            .form(&[
                ("csrf_token", csrf.as_str()),
                ("username", username.as_str()),
                ("email", shared_email.as_str()),
                ("password", "SecurePassword123!"),
                ("is_active", "on"),
            ])
            .await;
        assert_status(&resp, 303);
        let location = resp
            .headers()
            .get(LOCATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            location.starts_with("/accounts/users/") && !location.ends_with("/new"),
            "create '{}' with a shared e-mail must succeed and redirect to the \
             detail page, but Location was '{}'",
            username,
            location
        );
    }

    assert_eq!(
        active_holders(&mut conn, &shared_email).await,
        2,
        "both accounts must be ACTIVE under the shared e-mail"
    );

    // Each account remains individually addressable by its username --
    // the identity key is untouched by the shared address.
    for username in &usernames {
        let row: i64 = unwrap_ok!(
            users::table
                .filter(users::username.eq(username))
                .filter(users::is_deleted.eq(false))
                .count()
                .get_result(&mut conn)
                .await
        );
        assert_eq!(row, 1, "'{}' must exist exactly once", username);
    }

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// 2. Web edit: pointing an account at an already-used e-mail succeeds
// =============================================================================

/// Editing user B so that its e-mail becomes user A's address must be
/// accepted (it used to bounce with "Username or email already exists")
/// and must persist.
#[tokio::test]
#[serial]
async fn test_e2e_edit_user_onto_existing_email_succeeds() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin =
        create_admin_user(&mut conn, &app.auth_service, &unique_name("email_edit_adm")).await;
    let csrf = app.generate_csrf_token();

    let user_a = create_test_user(&mut conn, &app.auth_service, &unique_name("email_a")).await;
    let user_b = create_test_user(&mut conn, &app.auth_service, &unique_name("email_b")).await;

    let resp = app
        .server
        .post(&format!("/accounts/users/{}", user_b.user.uuid))
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("username", user_b.user.username.as_str()),
            ("email", user_a.user.email.as_str()),
            ("is_active", "on"),
        ])
        .await;
    let status = resp.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "edit onto a shared e-mail must redirect (PRG), got {}",
        status
    );
    let location = resp
        .headers()
        .get(LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        !location.ends_with("/edit"),
        "edit onto a shared e-mail must NOT bounce back to the edit form, \
         but Location was '{}'",
        location
    );

    let b_email_now: String = unwrap_ok!(
        users::table
            .filter(users::id.eq(user_b.user.id))
            .select(users::email)
            .first(&mut conn)
            .await
    );
    assert_eq!(
        b_email_now, user_a.user.email,
        "the shared e-mail must have been persisted on user B"
    );
    assert_eq!(
        active_holders(&mut conn, &user_a.user.email).await,
        2,
        "A and B must now share the address"
    );

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// 3. Non-regression: duplicate USERNAME is still rejected
// =============================================================================

/// Relaxing the e-mail must NOT relax the identity key: creating a
/// second account with an existing active username (and a brand-new
/// e-mail) must still bounce to the form without writing anything.
#[tokio::test]
#[serial]
async fn test_e2e_duplicate_username_still_rejected_with_distinct_email() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(
        &mut conn,
        &app.auth_service,
        &unique_name("email_dupuser_adm"),
    )
    .await;
    let csrf = app.generate_csrf_token();

    let existing =
        create_test_user(&mut conn, &app.auth_service, &unique_name("email_dupuser")).await;

    let resp = app
        .server
        .post("/accounts/users")
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("username", existing.user.username.as_str()),
            ("email", &format!("{}@fresh.test", unique_name("fresh"))),
            ("password", "SecurePassword123!"),
            ("is_active", "on"),
        ])
        .await;
    assert_status(&resp, 303);
    let location = resp
        .headers()
        .get(LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(
        location, "/accounts/users/new",
        "duplicate username must still bounce to the create form"
    );

    let count: i64 = unwrap_ok!(
        users::table
            .filter(users::username.eq(&existing.user.username))
            .count()
            .get_result(&mut conn)
            .await
    );
    assert_eq!(count, 1, "no second row may exist for the username");

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// 4. DB invariants: catalog shape and raw INSERT path
// =============================================================================

/// The pg catalog must carry NO unique constraint and NO unique index
/// on `users.email` (however named -- dump-restored installs included),
/// while the case-insensitive username sentinel `idx_users_username_lower`
/// must still be present. This asserts the OUTCOME of the migration on
/// the live schema, not just its SQL text.
#[tokio::test]
#[serial]
async fn db_catalog_has_no_email_uniqueness_and_keeps_username_sentinel() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let unique_constraints: CountRow = unwrap_ok!(
        diesel::sql_query(
            "SELECT COUNT(*)::bigint AS n
             FROM pg_constraint c
             WHERE c.conrelid = 'users'::regclass
               AND c.contype = 'u'
               AND c.conkey = ARRAY[
                   (SELECT attnum FROM pg_attribute
                    WHERE attrelid = 'users'::regclass AND attname = 'email')
               ]::smallint[]"
        )
        .get_result(&mut conn)
        .await
    );
    assert_eq!(
        unique_constraints.n, 0,
        "no unique constraint may remain on users.email"
    );

    let unique_email_indexes: CountRow = unwrap_ok!(
        diesel::sql_query(
            "SELECT COUNT(*)::bigint AS n
             FROM pg_indexes
             WHERE tablename = 'users'
               AND indexdef ILIKE 'CREATE UNIQUE INDEX%'
               AND indexdef ILIKE '%email%'"
        )
        .get_result(&mut conn)
        .await
    );
    assert_eq!(
        unique_email_indexes.n, 0,
        "no unique index (plain or expression) may cover users.email"
    );

    let username_sentinel: CountRow = unwrap_ok!(
        diesel::sql_query(
            "SELECT COUNT(*)::bigint AS n
             FROM pg_indexes
             WHERE tablename = 'users'
               AND indexname = 'idx_users_username_lower'
               AND indexdef ILIKE 'CREATE UNIQUE INDEX%'"
        )
        .get_result(&mut conn)
        .await
    );
    assert_eq!(
        username_sentinel.n, 1,
        "the case-insensitive username unique index must remain untouched"
    );
}

/// Battle test of the raw INSERT path (the exact statement the API and
/// IPC provisioning run, with no application-level duplicate check in
/// front): two rows with the same e-mail must both insert without a
/// UniqueViolation.
#[tokio::test]
#[serial]
async fn db_insert_two_rows_same_email_no_unique_violation() {
    use vauban_web::models::user::{AuthSource, NewUser};

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let shared_email = format!("{}@raw-insert.test", unique_name("dup"));
    for label in ["raw_a", "raw_b"] {
        let username = unique_name(label);
        let new_user = NewUser {
            uuid: uuid::Uuid::new_v4(),
            username: username.clone(),
            email: shared_email.clone(),
            password_hash: unwrap_ok!(app.auth_service.hash_password("SecurePassword123!")),
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
        let inserted = diesel::insert_into(users::table)
            .values(&new_user)
            .execute(&mut conn)
            .await;
        assert!(
            inserted.is_ok(),
            "raw INSERT of '{}' with the shared e-mail must succeed, got {:?}",
            username,
            inserted.err()
        );
    }

    assert_eq!(active_holders(&mut conn, &shared_email).await, 2);

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// 5. Structural pins
// =============================================================================

/// The web create/update handlers must no longer fold the e-mail into
/// their duplicate check: the only application-level gate left is the
/// username.
#[test]
fn web_user_handlers_gate_on_username_only() {
    assert!(
        !USERS_WEB_SRC.contains(".or(users::email.eq"),
        "create/update_user_web must not OR the e-mail into the duplicate lookup"
    );
    assert!(
        !USERS_WEB_SRC.contains("Username or email already exists"),
        "the combined duplicate error message must be gone"
    );
    assert!(
        USERS_WEB_SRC.contains("Username already exists"),
        "the username duplicate check must survive the e-mail relaxation"
    );
}

/// Login must keep resolving accounts by USERNAME only. If someone ever
/// adds a `users.email`-based credential lookup, shared addresses would
/// make authentication ambiguous -- this pin forces that conversation.
#[test]
fn login_never_resolves_users_by_email() {
    assert!(
        AUTH_SRC.contains("username.eq(&lookup_username)"),
        "the login handler must keep its username-based lookup"
    );
    assert!(
        !AUTH_SRC.contains("email.eq("),
        "handlers/auth.rs must never filter users by e-mail (shared \
         addresses would make the lookup ambiguous)"
    );
}

/// The supervisor's interactive superuser creation must no longer refuse
/// an already-used e-mail (the username prompt keeps its own check).
#[test]
fn supervisor_superuser_prompt_has_no_email_uniqueness_gate() {
    assert!(
        !SUPERVISOR_ADMIN_SRC.contains("Email '{input}' already exists"),
        "vauban-supervisor createsuperuser must not gate on e-mail uniqueness"
    );
    assert!(
        SUPERVISOR_ADMIN_SRC.contains("Username '{input}' already exists"),
        "the username uniqueness prompt-check must remain"
    );
}

/// The migration must drop the constraint by SHAPE (single-column unique
/// on `email` looked up in pg_constraint), not by hardcoded name only,
/// and the down path must restore the canonical constraint.
#[test]
fn migration_drops_email_unique_by_shape() {
    assert!(
        MIGRATION_UP_SQL.contains("contype = 'u'")
            && MIGRATION_UP_SQL.contains("attname = 'email'")
            && MIGRATION_UP_SQL.contains("DROP CONSTRAINT"),
        "up.sql must look the unique constraint up by shape and drop it"
    );
    assert!(
        MIGRATION_DOWN_SQL.contains("ADD CONSTRAINT users_email_key UNIQUE (email)"),
        "down.sql must restore the canonical users_email_key constraint"
    );
}
