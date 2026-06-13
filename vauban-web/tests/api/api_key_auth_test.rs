//! VAUBAN Web - API key (M2M) authentication E2E tests (VAU-007).
//!
//! Real HTTP, real Postgres: these tests drive the production
//! `auth_middleware` API-key-only branch and the `api_scope_enforcement`
//! layer through `build_test_router`. They cement the four invariants:
//!
//! - INV-1 (M2M-only): a human JWT never authenticates on `/api/v1/*`, and
//!   a `vbn_` key never authenticates a web route.
//! - INV-2 (fail-closed): a missing / unknown / revoked / expired key, or a
//!   deactivated owner, yields 401 and never injects an `AuthUser`.
//! - INV-3 (scope <= role): the effective right is the key scope ANDed with
//!   the owner's Casbin role; an insufficient scope yields 403.
//! - INV-4 is pinned separately in `tests/security/api_key_invariants_test.rs`.

use axum::http::header;
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::RunQueryDsl;
use serde_json::json;
use serial_test::serial;
use uuid::Uuid;

use vauban_web::models::api_key::{ApiKey, ApiKeyScope};

use crate::common::{TestApp, assertions::*, test_db};
use crate::fixtures::{
    create_admin_user, create_real_api_key, create_test_ssh_asset, create_test_user, unique_name,
};

/// X-API-Key header value (the alternative to `Authorization: Bearer`).
fn x_api_key(value: &str) -> header::HeaderValue {
    header::HeaderValue::from_str(value).expect("valid header value")
}

/// Read a key's `last_used_at` by its uuid.
async fn last_used_at(
    conn: &mut diesel_async::AsyncPgConnection,
    key_uuid: Uuid,
) -> Option<chrono::DateTime<chrono::Utc>> {
    use vauban_web::schema::api_keys;
    api_keys::table
        .filter(api_keys::uuid.eq(key_uuid))
        .select(api_keys::last_used_at)
        .first::<Option<chrono::DateTime<chrono::Utc>>>(conn)
        .await
        .expect("key row exists")
}

// =============================================================================
// INV-3: scope hierarchy enforced end-to-end
// =============================================================================

/// A read-scoped key authenticates a safe GET and stamps `last_used_at`.
#[tokio::test]
#[serial]
async fn read_key_authenticates_get() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("apikey_read")).await;
    let (key_uuid, raw_key) =
        create_real_api_key(&mut conn, user.user.id, &[ApiKeyScope::Read], None).await;

    assert!(
        last_used_at(&mut conn, key_uuid).await.is_none(),
        "fresh key must have no last_used_at"
    );

    let response = app
        .server
        .get("/api/v1/assets")
        .add_header(header::AUTHORIZATION, app.api_key_header(&raw_key))
        .await;
    assert_status(&response, 200);

    assert!(
        last_used_at(&mut conn, key_uuid).await.is_some(),
        "a successful authentication must stamp last_used_at"
    );

    test_db::cleanup(&mut conn).await;
}

/// The `X-API-Key` header is an accepted alternative to `Bearer`.
#[tokio::test]
#[serial]
async fn x_api_key_header_authenticates() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("apikey_xhdr")).await;
    let (_uuid, raw_key) =
        create_real_api_key(&mut conn, user.user.id, &[ApiKeyScope::Read], None).await;

    let response = app
        .server
        .get("/api/v1/assets")
        .add_header("X-API-Key", x_api_key(&raw_key))
        .await;
    assert_status(&response, 200);

    test_db::cleanup(&mut conn).await;
}

/// A read-scoped key is rejected (403) on a mutation: the scope gate fires
/// before the handler, regardless of the owner's role.
#[tokio::test]
#[serial]
async fn read_key_denied_on_mutation() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("apikey_romut")).await;
    let (_uuid, raw_key) =
        create_real_api_key(&mut conn, user.user.id, &[ApiKeyScope::Read], None).await;

    let response = app
        .server
        .post("/api/v1/sessions")
        .add_header(header::AUTHORIZATION, app.api_key_header(&raw_key))
        .json(&json!({ "asset_uuid": Uuid::new_v4().to_string(), "protocol": "ssh" }))
        .await;
    assert_status(&response, 403);

    test_db::cleanup(&mut conn).await;
}

/// A write-scoped key is rejected (403) on the admin zone; an admin-scoped
/// key (owned by a superuser) passes the scope gate AND Casbin.
#[tokio::test]
#[serial]
async fn write_key_denied_on_admin_zone_admin_key_allowed() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin =
        create_admin_user(&mut conn, &app.auth_service, &unique_name("apikey_adminz")).await;

    let (_w_uuid, write_key) =
        create_real_api_key(&mut conn, admin.user.id, &[ApiKeyScope::Write], None).await;
    let (_a_uuid, admin_key) =
        create_real_api_key(&mut conn, admin.user.id, &[ApiKeyScope::Admin], None).await;

    // write scope cannot reach the admin zone -> 403 (scope gate).
    let response = app
        .server
        .post("/api/v1/assets/manage")
        .add_header(header::AUTHORIZATION, app.api_key_header(&write_key))
        .json(&json!({
            "name": unique_name("apikey-asset"),
            "hostname": "host.example.com",
            "port": 22,
            "asset_type": "ssh"
        }))
        .await;
    assert_status(&response, 403);

    // admin scope (superuser owner) passes scope AND Casbin -> created.
    let response = app
        .server
        .post("/api/v1/assets/manage")
        .add_header(header::AUTHORIZATION, app.api_key_header(&admin_key))
        .json(&json!({
            "name": unique_name("apikey-asset"),
            "hostname": format!("{}.example.com", unique_name("apikeyhost")),
            "port": 22,
            "asset_type": "ssh"
        }))
        .await;
    let status = response.status_code().as_u16();
    assert!(
        (200..300).contains(&status),
        "admin-scoped key on the admin zone must pass the scope gate and Casbin, got {status}"
    );

    test_db::cleanup(&mut conn).await;
}

/// Admin scope satisfies a read (hierarchy admin >= read), end-to-end.
#[tokio::test]
#[serial]
async fn admin_key_can_read() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin =
        create_admin_user(&mut conn, &app.auth_service, &unique_name("apikey_adminr")).await;
    let (_uuid, raw_key) =
        create_real_api_key(&mut conn, admin.user.id, &[ApiKeyScope::Admin], None).await;

    let response = app
        .server
        .get("/api/v1/assets")
        .add_header(header::AUTHORIZATION, app.api_key_header(&raw_key))
        .await;
    assert_status(&response, 200);

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// INV-2: fail-closed
// =============================================================================

/// A nonexistent key is rejected with 401.
#[tokio::test]
#[serial]
async fn nonexistent_key_rejected() {
    let app = TestApp::spawn().await;

    let response = app
        .server
        .get("/api/v1/assets")
        .add_header(
            header::AUTHORIZATION,
            app.api_key_header(
                "vbn_0000000000000000000000000000000000000000000000000000000000000000",
            ),
        )
        .await;
    assert_status(&response, 401);
}

/// A revoked (is_active=false) key is rejected with 401.
#[tokio::test]
#[serial]
async fn revoked_key_rejected() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("apikey_revoked")).await;
    let (key_uuid, raw_key) =
        create_real_api_key(&mut conn, user.user.id, &[ApiKeyScope::Read], None).await;

    {
        use vauban_web::schema::api_keys;
        diesel::update(api_keys::table.filter(api_keys::uuid.eq(key_uuid)))
            .set(api_keys::is_active.eq(false))
            .execute(&mut conn)
            .await
            .expect("revoke key");
    }

    let response = app
        .server
        .get("/api/v1/assets")
        .add_header(header::AUTHORIZATION, app.api_key_header(&raw_key))
        .await;
    assert_status(&response, 401);

    test_db::cleanup(&mut conn).await;
}

/// An expired key is rejected with 401.
#[tokio::test]
#[serial]
async fn expired_key_rejected() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("apikey_expired")).await;
    let past = chrono::Utc::now() - chrono::Duration::hours(1);
    let (_uuid, raw_key) =
        create_real_api_key(&mut conn, user.user.id, &[ApiKeyScope::Read], Some(past)).await;

    let response = app
        .server
        .get("/api/v1/assets")
        .add_header(header::AUTHORIZATION, app.api_key_header(&raw_key))
        .await;
    assert_status(&response, 401);

    test_db::cleanup(&mut conn).await;
}

/// A key whose owner has been deactivated is rejected with 401 (extends
/// the SEC-07 deactivation guarantee to the M2M surface).
#[tokio::test]
#[serial]
async fn deactivated_owner_disables_key() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("apikey_deact")).await;
    let (_uuid, raw_key) =
        create_real_api_key(&mut conn, user.user.id, &[ApiKeyScope::Read], None).await;

    {
        use vauban_web::schema::users;
        diesel::update(users::table.filter(users::id.eq(user.user.id)))
            .set(users::is_active.eq(false))
            .execute(&mut conn)
            .await
            .expect("deactivate owner");
    }

    let response = app
        .server
        .get("/api/v1/assets")
        .add_header(header::AUTHORIZATION, app.api_key_header(&raw_key))
        .await;
    assert_status(&response, 401);

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// INV-1: M2M-only (both directions)
// =============================================================================

/// A valid post-MFA human JWT is refused on the API (API-key-only).
#[tokio::test]
#[serial]
async fn human_jwt_refused_on_api() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // `create_test_user` mints an mfa_verified=true (post-MFA) session JWT.
    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("apikey_jwt")).await;

    let response = app
        .server
        .get("/api/v1/assets")
        .add_header(header::AUTHORIZATION, app.auth_header(&user.token))
        .await;
    assert_status(&response, 401);

    test_db::cleanup(&mut conn).await;
}

/// A valid API key does NOT authenticate a web route (reciprocal of INV-1).
#[tokio::test]
#[serial]
async fn api_key_does_not_work_on_web_route() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("apikey_web")).await;
    let (_uuid, raw_key) =
        create_real_api_key(&mut conn, user.user.id, &[ApiKeyScope::Admin], None).await;

    // Web route: a key in either header form must NOT authenticate. The
    // WebAuthUser extractor redirects unauthenticated callers to /login.
    let response = app
        .server
        .get("/accounts/apikeys")
        .add_header(header::AUTHORIZATION, app.api_key_header(&raw_key))
        .add_header("X-API-Key", x_api_key(&raw_key))
        .await;
    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 401,
        "an API key must not authenticate a web route, got {status}"
    );

    test_db::cleanup(&mut conn).await;
}

/// The X-API-Key extractor and hashing line up with the production model.
#[tokio::test]
#[serial]
async fn generated_key_hash_matches_model() {
    // Sanity pin: `create_real_api_key` stores `ApiKey::hash_key(raw)`.
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("apikey_hash")).await;
    let (key_uuid, raw_key) =
        create_real_api_key(&mut conn, user.user.id, &[ApiKeyScope::Read], None).await;

    use vauban_web::schema::api_keys;
    let stored_hash: String = api_keys::table
        .filter(api_keys::uuid.eq(key_uuid))
        .select(api_keys::key_hash)
        .first(&mut conn)
        .await
        .expect("key row");
    assert_eq!(stored_hash, ApiKey::hash_key(&raw_key));

    // Touch the asset fixture so the import is always exercised.
    let _ = create_test_ssh_asset(&mut conn, &unique_name("apikey-hash-asset")).await;

    test_db::cleanup(&mut conn).await;
}
