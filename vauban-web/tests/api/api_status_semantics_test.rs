//! VAUBAN Web - `/api/v1` honest status semantics E2E matrix.
//!
//! Pins the invariants of
//! [`vauban_web::services::api_response_invariants`] end-to-end over
//! real HTTP, real Postgres and the in-process Casbin oracle:
//!
//! - INV-API-2: missing or invalid API key -> 401.
//! - INV-API-3: valid key but not authorized -> 403, whatever the
//!   layer that refuses (key scope, Casbin capability, instance-level
//!   session ownership).
//! - INV-API-4: authorized but the resource does not exist -> 404.
//! - INV-API-5: malformed UUID -> 400 (no phantom 404).
//!
//! The vault-specific matrix (provenance 403, rule-level 403,
//! non-existence 404, malformed 400) lives in `vault_secrets_test.rs`
//! and `vault_provenance_test.rs`; the `api.enabled = false` 501 lives
//! in `api_disabled_test.rs`.

use axum::http::header;
use serial_test::serial;
use uuid::Uuid;

use vauban_web::models::api_key::ApiKeyScope;

use crate::common::{TestApp, assertions::*, test_db};
use crate::fixtures::{
    create_admin_user, create_real_api_key, create_simple_ssh_asset, create_test_session_with_uuid,
    create_test_user, grant_user_access_to_asset, unique_name,
};

// =============================================================================
// INV-API-2: no key / invalid key -> 401
// =============================================================================

/// Without any Authorization header, every representative endpoint of
/// the M2M zone answers 401.
#[tokio::test]
#[serial]
async fn missing_api_key_is_401_everywhere() {
    let app = TestApp::spawn().await;

    for path in [
        "/api/v1/sessions",
        "/api/v1/accounts",
        "/api/v1/assets",
        "/api/v1/vault/secrets",
    ] {
        let response = app.server.get(path).await;
        assert_eq!(
            response.status_code().as_u16(),
            401,
            "GET {path} without a key must be 401"
        );
    }
}

/// A syntactically plausible but unknown key answers 401 (not 403:
/// the caller is not authenticated at all).
#[tokio::test]
#[serial]
async fn invalid_api_key_is_401() {
    let app = TestApp::spawn().await;

    let forged = format!("vbn_{}", "a".repeat(43));
    for path in ["/api/v1/sessions", "/api/v1/vault/secrets"] {
        let response = app
            .server
            .get(path)
            .add_header(header::AUTHORIZATION, app.api_key_header(&forged))
            .await;
        assert_eq!(
            response.status_code().as_u16(),
            401,
            "GET {path} with a forged key must be 401"
        );
    }
}

// =============================================================================
// INV-API-3: valid key, not authorized -> 403 (scope / Casbin / instance)
// =============================================================================

/// Key-scope refusal: a `read`-scoped key on the vault zone (requires
/// the dedicated `secrets` scope) and a `secrets`-scoped key on the
/// read zone are both 403.
#[tokio::test]
#[serial]
async fn wrong_key_scope_is_403() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("sem_scope")).await;

    let (_uuid, read_key) =
        create_real_api_key(&mut conn, admin.user.id, &[ApiKeyScope::Read], None).await;
    let response = app
        .server
        .get("/api/v1/vault/secrets")
        .add_header(header::AUTHORIZATION, app.api_key_header(&read_key))
        .await;
    assert_status(&response, 403);
    assert!(
        response.text().contains("API key lacks required scope"),
        "scope denial must carry the canonical message"
    );

    let (_uuid, secrets_key) =
        create_real_api_key(&mut conn, admin.user.id, &[ApiKeyScope::Secrets], None).await;
    let response = app
        .server
        .get("/api/v1/assets")
        .add_header(header::AUTHORIZATION, app.api_key_header(&secrets_key))
        .await;
    assert_status(&response, 403);

    test_db::cleanup(&mut conn).await;
}

/// Casbin capability refusal: a regular user (admin-scoped key, but no
/// `users:read` role grant) listing accounts is 403 with the canonical
/// "Insufficient privileges" message.
#[tokio::test]
#[serial]
async fn casbin_denied_capability_is_403() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("sem_casbin")).await;

    let response = app
        .server
        .get("/api/v1/accounts")
        .add_header(header::AUTHORIZATION, app.api_key_header(&user.api_key))
        .await;
    assert_status(&response, 403);
    assert!(
        response.text().contains("Insufficient privileges"),
        "Casbin denial must carry the canonical message"
    );

    test_db::cleanup(&mut conn).await;
}

/// Instance-level refusal: user B (valid key, `sessions:read` granted
/// by role) reading or terminating user A's session gets 403 — the
/// session exists, B is simply not authorized. 404 is reserved for
/// non-existent sessions (INV-API-4, next test).
#[tokio::test]
#[serial]
async fn existing_but_foreign_session_is_403() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let owner = create_test_user(&mut conn, &app.auth_service, &unique_name("sem_owner")).await;
    let intruder =
        create_test_user(&mut conn, &app.auth_service, &unique_name("sem_intruder")).await;

    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("sem_asset"), owner.user.id).await;
    grant_user_access_to_asset(
        &mut conn,
        owner.user.id,
        asset_id,
        &unique_name("sem_grant"),
        &["ssh"],
    )
    .await;
    let (_sid, session_uuid) =
        create_test_session_with_uuid(&mut conn, owner.user.id, asset_id, "ssh", "active").await;
    drop(conn);

    let response = app
        .server
        .get(&format!("/api/v1/sessions/{session_uuid}"))
        .add_header(header::AUTHORIZATION, app.api_key_header(&intruder.api_key))
        .await;
    assert_status(&response, 403);
    assert!(
        response
            .text()
            .contains("Not authorized to access this session"),
        "foreign-session read must carry the canonical 403 message"
    );

    let response = app
        .server
        .post(&format!("/api/v1/sessions/{session_uuid}/terminate"))
        .add_header(header::AUTHORIZATION, app.api_key_header(&intruder.api_key))
        .await;
    assert_status(&response, 403);

    // The owner still reads their own session fine (sanity).
    let response = app
        .server
        .get(&format!("/api/v1/sessions/{session_uuid}"))
        .add_header(header::AUTHORIZATION, app.api_key_header(&owner.api_key))
        .await;
    assert_status(&response, 200);
}

// =============================================================================
// INV-API-4: authorized but non-existent -> 404
// =============================================================================

/// A session UUID that matches no row is an honest 404 for any caller
/// holding `sessions:read` — regular user and supervisor alike (the
/// Casbin override never resurrects a non-existent resource).
#[tokio::test]
#[serial]
async fn unknown_session_uuid_is_404() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("sem_404")).await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("sem_404a")).await;
    drop(conn);

    let ghost = Uuid::new_v4();
    for key in [&user.api_key, &admin.api_key] {
        let response = app
            .server
            .get(&format!("/api/v1/sessions/{ghost}"))
            .add_header(header::AUTHORIZATION, app.api_key_header(key))
            .await;
        assert_status(&response, 404);
        assert!(
            response.text().contains("Session not found"),
            "non-existence must carry the canonical 404 message"
        );
    }
}

// =============================================================================
// INV-API-5: malformed UUID -> 400
// =============================================================================

/// A non-UUID path segment is a 400 Bad Request on the session
/// endpoints (both read and terminate), never a phantom 404.
#[tokio::test]
#[serial]
async fn malformed_session_uuid_is_400() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("sem_400")).await;
    drop(conn);

    let response = app
        .server
        .get("/api/v1/sessions/not-a-uuid")
        .add_header(header::AUTHORIZATION, app.api_key_header(&user.api_key))
        .await;
    assert_status(&response, 400);
    assert!(
        response.text().contains("Invalid UUID format"),
        "malformed UUID must carry the canonical 400 message"
    );

    let response = app
        .server
        .post("/api/v1/sessions/not-a-uuid/terminate")
        .add_header(header::AUTHORIZATION, app.api_key_header(&user.api_key))
        .await;
    assert_status(&response, 400);
}
