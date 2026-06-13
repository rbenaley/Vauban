//! VAUBAN Web - Session IDOR security tests.
//!
//! These tests cement the post-audit guarantee that EVERY consumer of
//! an existing `proxy_sessions` row routes through
//! [`vauban_web::services::session_access::verify`], itself backed by
//! the vauban-access `VerifySessionAccess` RPC. Without that, an
//! authenticated user that knew (or guessed) a session UUID would be
//! able to:
//!
//! - render the RDP viewer page of someone else's session (`rdp_page`
//!   used to have NO ownership check at all);
//! - terminate someone else's session through the API or web routes
//!   (only `sessions:write` was checked, never ownership);
//! - read someone else's session metadata via
//!   `GET /api/v1/sessions/{uuid}` (only `sessions:read` Casbin gate);
//! - list every session globally via `GET /api/v1/sessions` (no
//!   per-caller filter applied);
//! - subscribe to the global WebSocket session feeds without holding
//!   `admin:view` (the read-only audit gate).
//!
//! Each test below builds two distinct users, assigns the owner an
//! active access rule, opens a session for the owner, and proves that
//! the attacker's probe collapses to 404 / Forbidden / unauthorized as
//! appropriate. Anti-enumeration is paramount: 404 is the canonical
//! response for "not yours / does not exist / rule revoked".

use axum::http::header;
use serial_test::serial;

use crate::common::TestApp;
use crate::fixtures::{
    create_simple_admin_user, create_simple_rdp_asset, create_simple_ssh_asset,
    create_test_session_with_uuid, create_test_user, grant_user_access_to_asset, unique_name,
};

// === Helpers (kept here so the file is self-contained / readable) ===

/// SSH terminal HTML wrapper.
async fn terminal_page_get(
    app: &TestApp,
    session_uuid: &str,
    token: &str,
) -> axum_test::TestResponse {
    app.server
        .get(&format!("/sessions/terminal/{}", session_uuid))
        .add_header(header::COOKIE, format!("access_token={}", token))
        .await
}

/// RDP viewer HTML wrapper.
async fn rdp_page_get(app: &TestApp, session_uuid: &str, token: &str) -> axum_test::TestResponse {
    app.server
        .get(&format!("/sessions/rdp/{}", session_uuid))
        .add_header(header::COOKIE, format!("access_token={}", token))
        .await
}

/// API metadata read (`GET /api/v1/sessions/{uuid}`).
///
/// VAU-007: the `/api/v1/*` zone is API-key-only, so the M2M caller
/// authenticates with a `vbn_` key (the owner's Casbin role still drives
/// the session-access decision).
async fn api_get_session(
    app: &TestApp,
    session_uuid: &str,
    api_key: &str,
) -> axum_test::TestResponse {
    app.server
        .get(&format!("/api/v1/sessions/{}", session_uuid))
        .add_header(header::AUTHORIZATION, app.api_key_header(api_key))
        .await
}

/// API list sessions (`GET /api/v1/sessions`).
async fn api_list_sessions(app: &TestApp, api_key: &str) -> axum_test::TestResponse {
    app.server
        .get("/api/v1/sessions")
        .add_header(header::AUTHORIZATION, app.api_key_header(api_key))
        .await
}

// =============================================================================
// rdp_page IDOR (the cosmetic but real audit finding)
// =============================================================================

/// SECURITY (anti-IDOR): user B that knows the UUID of user A's RDP
/// session must NOT receive the viewer HTML wrapper. Today (pre-fix)
/// `rdp_page` has zero ownership / access checks and returns 200 for
/// anybody, letting an attacker enumerate session UUIDs.
#[tokio::test]
#[serial]
async fn test_user_b_cannot_open_user_a_rdp_page() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let owner = create_test_user(&mut conn, &app.auth_service, &unique_name("idor_rdp_a")).await;
    let attacker = create_test_user(&mut conn, &app.auth_service, &unique_name("idor_rdp_b")).await;

    let asset_id =
        create_simple_rdp_asset(&mut conn, &unique_name("idor_rdp_asset"), owner.user.id).await;
    grant_user_access_to_asset(
        &mut conn,
        owner.user.id,
        asset_id,
        &unique_name("idor_rdp_grant"),
        &["rdp"],
    )
    .await;
    let (_sid, session_uuid) =
        create_test_session_with_uuid(&mut conn, owner.user.id, asset_id, "rdp", "active").await;

    drop(conn);

    let resp = rdp_page_get(app, &session_uuid.to_string(), &attacker.token).await;
    let status = resp.status_code().as_u16();
    assert_eq!(
        status, 404,
        "rdp_page must collapse non-owner probes to 404 (anti-enum), \
         got {}. Without the fix, the IDOR returns 200.",
        status
    );
}

/// Companion non-regression: legitimate owner still receives the RDP
/// HTML wrapper after the fix.
#[tokio::test]
#[serial]
async fn test_owner_can_open_own_rdp_page() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let owner = create_test_user(&mut conn, &app.auth_service, &unique_name("rdp_okown")).await;
    let asset_id =
        create_simple_rdp_asset(&mut conn, &unique_name("rdp_okown_asset"), owner.user.id).await;
    grant_user_access_to_asset(
        &mut conn,
        owner.user.id,
        asset_id,
        &unique_name("rdp_okown_grant"),
        &["rdp"],
    )
    .await;
    let (_sid, session_uuid) =
        create_test_session_with_uuid(&mut conn, owner.user.id, asset_id, "rdp", "active").await;

    drop(conn);

    let resp = rdp_page_get(app, &session_uuid.to_string(), &owner.token).await;
    let status = resp.status_code().as_u16();
    assert_eq!(
        status, 200,
        "Session owner must keep receiving the RDP HTML wrapper after \
         the IDOR fix, got {}",
        status
    );
}

// =============================================================================
// terminal_page (already protected, kept under regression watch)
// =============================================================================

/// SECURITY: terminal_page must continue to collapse non-owner probes
/// to 404 after the migration to `session_access::verify`.
#[tokio::test]
#[serial]
async fn test_user_b_cannot_open_user_a_terminal_page() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let owner = create_test_user(&mut conn, &app.auth_service, &unique_name("idor_term_a")).await;
    let attacker =
        create_test_user(&mut conn, &app.auth_service, &unique_name("idor_term_b")).await;

    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("idor_term_asset"), owner.user.id).await;
    grant_user_access_to_asset(
        &mut conn,
        owner.user.id,
        asset_id,
        &unique_name("idor_term_grant"),
        &["ssh"],
    )
    .await;
    let (_sid, session_uuid) =
        create_test_session_with_uuid(&mut conn, owner.user.id, asset_id, "ssh", "active").await;

    drop(conn);

    let resp = terminal_page_get(app, &session_uuid.to_string(), &attacker.token).await;
    let status = resp.status_code().as_u16();
    assert_eq!(
        status, 404,
        "terminal_page must keep collapsing non-owner probes to 404, got {}",
        status
    );
}

// =============================================================================
// terminate_session (web + API): owner OR sessions:write
// =============================================================================

/// SECURITY (anti-IDOR): a regular user must NOT be able to terminate
/// someone else's session via the API. Today (pre-fix) the API only
/// checks `sessions:write`, so a staff/superuser can kill any session
/// AND a regular user that holds the perm could too.
#[tokio::test]
#[serial]
async fn test_user_b_cannot_terminate_user_a_session_via_api() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let owner = create_test_user(&mut conn, &app.auth_service, &unique_name("term_a")).await;
    let attacker = create_test_user(&mut conn, &app.auth_service, &unique_name("term_b")).await;

    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("term_asset"), owner.user.id).await;
    grant_user_access_to_asset(
        &mut conn,
        owner.user.id,
        asset_id,
        &unique_name("term_grant"),
        &["ssh"],
    )
    .await;
    let (_sid, session_uuid) =
        create_test_session_with_uuid(&mut conn, owner.user.id, asset_id, "ssh", "active").await;

    drop(conn);

    let resp = app
        .server
        .post(&format!("/api/v1/sessions/{}/terminate", session_uuid))
        .add_header(header::AUTHORIZATION, app.api_key_header(&attacker.api_key))
        .await;
    let status = resp.status_code().as_u16();
    // 404 is the anti-enum collapse for NotOwner-without-write. Some
    // pre-existing routes happen to surface 403 for an authenticated
    // user that lacks Casbin sessions:write entirely; the migration
    // unifies on 404 (anti-enum).
    assert_eq!(
        status, 404,
        "regular user must NOT terminate another user's session via API, got {}",
        status
    );
}

// =============================================================================
// API metadata read: get_session must filter on owner OR supervisor
// =============================================================================

/// SECURITY (anti-IDOR): a user with `sessions:read` (e.g. staff role)
/// but NOT `sessions:supervise` must NOT be able to read another
/// user's session metadata. Today the handler only checks
/// `sessions:read` Casbin and returns the row to anybody who knows
/// the UUID.
///
/// This test pins the matrix once `sessions_supervise` is reserved to
/// the superuser policy line. If the policy file changes the staff
/// scope of `sessions:supervise`, update this test to use a
/// non-superuser non-staff caller that explicitly lacks supervise.
#[tokio::test]
#[serial]
async fn test_user_b_cannot_get_user_a_session_metadata() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let owner = create_test_user(&mut conn, &app.auth_service, &unique_name("meta_a")).await;
    let attacker = create_test_user(&mut conn, &app.auth_service, &unique_name("meta_b")).await;

    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("meta_asset"), owner.user.id).await;
    grant_user_access_to_asset(
        &mut conn,
        owner.user.id,
        asset_id,
        &unique_name("meta_grant"),
        &["ssh"],
    )
    .await;
    let (_sid, session_uuid) =
        create_test_session_with_uuid(&mut conn, owner.user.id, asset_id, "ssh", "active").await;

    drop(conn);

    let resp = api_get_session(app, &session_uuid.to_string(), &attacker.api_key).await;
    let status = resp.status_code().as_u16();
    assert_eq!(
        status, 404,
        "regular user must NOT read another user's session metadata, got {}",
        status
    );
}

// =============================================================================
// list_sessions API: per-caller filter must apply unless supervisor
// =============================================================================

/// SECURITY (anti-IDOR): listing sessions as a regular user must only
/// surface that user's own sessions. Today the handler returns every
/// row that matches `sessions:read` Casbin, leaking session UUIDs of
/// every other user.
#[tokio::test]
#[serial]
async fn test_list_sessions_api_filters_to_caller_unless_supervise() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let owner = create_test_user(&mut conn, &app.auth_service, &unique_name("list_a")).await;
    let other = create_test_user(&mut conn, &app.auth_service, &unique_name("list_b")).await;

    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("list_asset"), owner.user.id).await;
    grant_user_access_to_asset(
        &mut conn,
        owner.user.id,
        asset_id,
        &unique_name("list_grant_a"),
        &["ssh"],
    )
    .await;
    grant_user_access_to_asset(
        &mut conn,
        other.user.id,
        asset_id,
        &unique_name("list_grant_b"),
        &["ssh"],
    )
    .await;

    let (_sid_a, session_uuid_a) =
        create_test_session_with_uuid(&mut conn, owner.user.id, asset_id, "ssh", "active").await;
    let (_sid_b, session_uuid_b) =
        create_test_session_with_uuid(&mut conn, other.user.id, asset_id, "ssh", "active").await;

    drop(conn);

    let resp = api_list_sessions(app, &owner.api_key).await;
    assert_eq!(resp.status_code().as_u16(), 200, "list must succeed");
    let body = resp.text();

    assert!(
        body.contains(&session_uuid_a.to_string()),
        "owner's own session must appear in the listing"
    );
    assert!(
        !body.contains(&session_uuid_b.to_string()),
        "other user's session UUID must NOT leak in the listing for a \
         caller without sessions:supervise"
    );
}

/// Companion: a superuser (with `sessions:supervise`) sees every
/// session in the list. Cements that the per-caller filter is
/// correctly suppressed for supervisors, so audit dashboards keep
/// working after the IDOR fix.
#[tokio::test]
#[serial]
async fn test_list_sessions_api_supervisor_sees_everything() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let owner = create_test_user(&mut conn, &app.auth_service, &unique_name("listsup_a")).await;
    let other = create_test_user(&mut conn, &app.auth_service, &unique_name("listsup_b")).await;
    let admin_id = create_simple_admin_user(&mut conn, &unique_name("listsup_admin")).await;

    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("listsup_asset"), owner.user.id).await;
    grant_user_access_to_asset(
        &mut conn,
        owner.user.id,
        asset_id,
        &unique_name("listsup_grant_a"),
        &["ssh"],
    )
    .await;
    grant_user_access_to_asset(
        &mut conn,
        other.user.id,
        asset_id,
        &unique_name("listsup_grant_b"),
        &["ssh"],
    )
    .await;

    let (_sid_a, session_uuid_a) =
        create_test_session_with_uuid(&mut conn, owner.user.id, asset_id, "ssh", "active").await;
    let (_sid_b, session_uuid_b) =
        create_test_session_with_uuid(&mut conn, other.user.id, asset_id, "ssh", "active").await;

    // VAU-007: the supervisor authenticates to the M2M API with an
    // admin-scoped API key. The `sessions:supervise` capability still comes
    // from the owner's superuser Casbin role, not from the key scope.
    let (_admin_key_uuid, admin_api_key) = crate::fixtures::create_real_api_key(
        &mut conn,
        admin_id,
        &[vauban_web::models::api_key::ApiKeyScope::Admin],
        None,
    )
    .await;
    drop(conn);

    let resp = api_list_sessions(app, &admin_api_key).await;
    assert_eq!(resp.status_code().as_u16(), 200, "list must succeed");
    let body = resp.text();

    assert!(
        body.contains(&session_uuid_a.to_string()) && body.contains(&session_uuid_b.to_string()),
        "supervisor must see every session UUID in the listing"
    );
}

// =============================================================================
// WebSocket global session feeds: must require admin:view
// =============================================================================

/// SECURITY: `/ws/sessions/list` (admin live feed) must require the
/// `admin:view` Casbin gate. Today the route is gated only by MFA and
/// the WS connection limit, so any authenticated user can subscribe
/// to the global session feed.
#[tokio::test]
#[serial]
async fn test_session_list_ws_requires_admin_view() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("wslist")).await;
    drop(conn);

    let resp = app
        .server
        .get("/ws/sessions/list")
        .add_header(header::AUTHORIZATION, app.auth_header(&user.token))
        .await;
    let status = resp.status_code().as_u16();
    assert!(
        status == 403 || status == 404,
        "/ws/sessions/list must reject regular users (admin:view gate). \
         Got {}.",
        status
    );
}

/// SECURITY: `/ws/sessions/active` (admin active sessions feed) must
/// require the `admin:view` Casbin gate. Same rationale as above.
#[tokio::test]
#[serial]
async fn test_active_sessions_ws_requires_admin_view() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("wsactive")).await;
    drop(conn);

    let resp = app
        .server
        .get("/ws/sessions/active")
        .add_header(header::AUTHORIZATION, app.auth_header(&user.token))
        .await;
    let status = resp.status_code().as_u16();
    assert!(
        status == 403 || status == 404,
        "/ws/sessions/active must reject regular users (admin:view gate). \
         Got {}.",
        status
    );
}
