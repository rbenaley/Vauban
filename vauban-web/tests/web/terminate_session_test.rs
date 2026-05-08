//! VAUBAN Web - terminate-session authorisation matrix.
//!
//! These tests cement the post-audit policy for both
//! `POST /sessions/{uuid}/terminate` (web/HTMX wrapper) and
//! `POST /api/v1/sessions/{uuid}/terminate` (JSON API):
//!
//!     allowed iff (caller == session.owner) OR (perms.sessions_write)
//!
//! Plus the strong anti-enumeration shape:
//!
//!     denied -> 404 (NEVER 403), so an attacker cannot fingerprint
//!     existing session UUIDs through latency/wording differences.
//!
//! On the side-effect axis, a successful terminate must also flip the
//! row to `terminated` and stamp `disconnected_at`, regardless of
//! whether the proxy backend is wired (test harness has no
//! ssh_proxy/rdp_proxy and that path is a no-op).

use axum::http::header::COOKIE;
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use uuid::Uuid;

use crate::common::{TestApp, assertions::assert_status, unwrap_ok};
use crate::fixtures::{
    create_simple_admin_user, create_simple_ssh_asset, create_simple_user,
    create_test_session_with_uuid, grant_user_access_to_asset, unique_name,
};

async fn get_user_uuid(conn: &mut AsyncPgConnection, user_id: i32) -> Uuid {
    use vauban_web::schema::users;
    unwrap_ok!(
        users::table
            .filter(users::id.eq(user_id))
            .select(users::uuid)
            .first(conn)
            .await
    )
}

async fn db_status(conn: &mut AsyncPgConnection, session_id: i32) -> String {
    use vauban_web::schema::proxy_sessions;
    unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::id.eq(session_id))
            .select(proxy_sessions::status)
            .first(conn)
            .await
    )
}

// =============================================================================
// 1. Owner can terminate own session via web
// =============================================================================

/// SECURITY: a regular (non-staff, non-superuser) user MUST be able
/// to terminate their own active session via the web/HTMX endpoint.
/// Today the handler refuses unless the caller has `sessions:write`,
/// which is the audit gap this test pins down.
#[tokio::test]
async fn test_owner_can_terminate_own_session_via_web() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let owner_name = unique_name("term_owner_web");
    let owner_id = create_simple_user(&mut conn, &owner_name).await;
    let owner_uuid = get_user_uuid(&mut conn, owner_id).await;

    let admin_id = create_simple_admin_user(&mut conn, &unique_name("term_owner_web_adm")).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("term_owner_web_ast"), admin_id).await;
    let _ = grant_user_access_to_asset(
        &mut conn,
        owner_id,
        asset_id,
        &unique_name("term_owner_web_grant"),
        &["ssh"],
    )
    .await;
    let (session_id, session_uuid) =
        create_test_session_with_uuid(&mut conn, owner_id, asset_id, "ssh", "active").await;

    let token = app
        .generate_test_token(&owner_uuid.to_string(), &owner_name, false, false)
        .await;
    let csrf_token = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/sessions/{}/terminate", session_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .add_header("HX-Request", "true")
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;

    assert_status(&response, 200);
    assert_eq!(
        db_status(&mut conn, session_id).await,
        "terminated",
        "owner-driven termination must flip the row to terminated"
    );
}

// =============================================================================
// 2. Owner can terminate own session via API
// =============================================================================

#[tokio::test]
async fn test_owner_can_terminate_own_session_via_api() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let owner_name = unique_name("term_owner_api");
    let owner_id = create_simple_user(&mut conn, &owner_name).await;
    let owner_uuid = get_user_uuid(&mut conn, owner_id).await;

    let admin_id = create_simple_admin_user(&mut conn, &unique_name("term_owner_api_adm")).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("term_owner_api_ast"), admin_id).await;
    let _ = grant_user_access_to_asset(
        &mut conn,
        owner_id,
        asset_id,
        &unique_name("term_owner_api_grant"),
        &["ssh"],
    )
    .await;
    let (session_id, session_uuid) =
        create_test_session_with_uuid(&mut conn, owner_id, asset_id, "ssh", "active").await;

    let token = app
        .generate_test_token(&owner_uuid.to_string(), &owner_name, false, false)
        .await;
    let csrf_token = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/api/v1/sessions/{}/terminate", session_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .add_header("X-CSRF-Token", csrf_token.as_str())
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 200,
        "owner must terminate via API (got {}): {:?}",
        status,
        response.text()
    );
    assert_eq!(db_status(&mut conn, session_id).await, "terminated");
}

// =============================================================================
// 3. Admin (sessions:write) can terminate someone else's session via API
// =============================================================================

#[tokio::test]
async fn test_admin_with_sessions_write_can_terminate_others_session_via_api() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let owner_name = unique_name("term_admin_other_owner");
    let owner_id = create_simple_user(&mut conn, &owner_name).await;
    let admin_name = unique_name("term_admin_other_adm");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("term_admin_other_ast"), admin_id).await;
    let _ = grant_user_access_to_asset(
        &mut conn,
        owner_id,
        asset_id,
        &unique_name("term_admin_other_grant"),
        &["ssh"],
    )
    .await;
    let (session_id, session_uuid) =
        create_test_session_with_uuid(&mut conn, owner_id, asset_id, "ssh", "active").await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let csrf_token = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/api/v1/sessions/{}/terminate", session_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .add_header("X-CSRF-Token", csrf_token.as_str())
        .await;

    assert_status(&response, 200);
    assert_eq!(db_status(&mut conn, session_id).await, "terminated");
}

// =============================================================================
// 4. Non-owner without sessions:write -> 404 (anti-enum)
// =============================================================================

/// SECURITY: a regular user (not the owner, no `sessions:write`) MUST
/// receive 404 (not 403, never the success page) when probing
/// someone else's session terminate endpoint. Today the handler
/// returns 403 ("sessions:write") and the row stays untouched, which
/// is correct on the side-effect axis but leaks the existence of the
/// session UUID through the status code. Post-fix this collapses to
/// 404 to align with the rest of the session_access surface.
#[tokio::test]
async fn test_user_without_sessions_write_cannot_terminate_others_session() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let owner_name = unique_name("term_other_owner");
    let owner_id = create_simple_user(&mut conn, &owner_name).await;
    let attacker_name = unique_name("term_other_atk");
    let attacker_id = create_simple_user(&mut conn, &attacker_name).await;
    let attacker_uuid = get_user_uuid(&mut conn, attacker_id).await;

    let admin_id = create_simple_admin_user(&mut conn, &unique_name("term_other_adm")).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("term_other_ast"), admin_id).await;
    let _ = grant_user_access_to_asset(
        &mut conn,
        owner_id,
        asset_id,
        &unique_name("term_other_grant"),
        &["ssh"],
    )
    .await;
    let (session_id, session_uuid) =
        create_test_session_with_uuid(&mut conn, owner_id, asset_id, "ssh", "active").await;

    let token = app
        .generate_test_token(&attacker_uuid.to_string(), &attacker_name, false, false)
        .await;
    let csrf_token = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/api/v1/sessions/{}/terminate", session_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .add_header("X-CSRF-Token", csrf_token.as_str())
        .await;

    assert_eq!(
        response.status_code().as_u16(),
        404,
        "non-owner without sessions:write must collapse to 404 (anti-enum)"
    );
    assert_eq!(
        db_status(&mut conn, session_id).await,
        "active",
        "victim's session must remain untouched"
    );
}

// =============================================================================
// 5. Successful terminate flips status + stamps disconnected_at
// =============================================================================

/// SECURITY/integrity: terminate must atomically flip the row to
/// `terminated` AND stamp `disconnected_at`. The proxy-side
/// `close_session` is exercised by integration in production; here we
/// pin the DB-level invariant which is what gates the WS cleanup
/// loop and the dashboard's "active sessions" gauge.
#[tokio::test]
async fn test_terminate_session_stamps_disconnected_at() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let owner_name = unique_name("term_proxy_owner");
    let owner_id = create_simple_user(&mut conn, &owner_name).await;
    let owner_uuid = get_user_uuid(&mut conn, owner_id).await;

    let admin_id = create_simple_admin_user(&mut conn, &unique_name("term_proxy_adm")).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("term_proxy_ast"), admin_id).await;
    let _ = grant_user_access_to_asset(
        &mut conn,
        owner_id,
        asset_id,
        &unique_name("term_proxy_grant"),
        &["ssh"],
    )
    .await;
    let (session_id, session_uuid) =
        create_test_session_with_uuid(&mut conn, owner_id, asset_id, "ssh", "active").await;

    let token = app
        .generate_test_token(&owner_uuid.to_string(), &owner_name, false, false)
        .await;
    let csrf_token = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/api/v1/sessions/{}/terminate", session_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .add_header("X-CSRF-Token", csrf_token.as_str())
        .await;
    assert_status(&response, 200);

    use vauban_web::schema::proxy_sessions;
    let (status, disc_at): (String, Option<chrono::DateTime<chrono::Utc>>) = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::id.eq(session_id))
            .select((proxy_sessions::status, proxy_sessions::disconnected_at))
            .first(&mut conn)
            .await
    );
    assert_eq!(status, "terminated");
    assert!(
        disc_at.is_some(),
        "disconnected_at must be stamped on terminate"
    );
}

// ---------------------------------------------------------------------------
// Issue #29 v1.4 -- the API terminate handler MUST schedule a
// recording integrity hydration (PRIMARY enqueue path) on the same
// code path that stamps `disconnected_at`. In test mode the
// supervisor is `None` and the enqueue is a silent no-op; we just
// assert the handler stays 200 (no panic, no 500), which is the
// behavioural contract: the enqueue is fire-and-forget and never
// degrades the user-visible response.
// ---------------------------------------------------------------------------
#[tokio::test]
#[serial_test::serial]
async fn test_api_terminate_does_not_panic_when_supervisor_absent() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Sanity: the test fixture has no supervisor (development mode).
    assert!(
        app.app_state.supervisor.is_none(),
        "fixture must be in development mode for this test"
    );

    let owner_name = unique_name("term_v14_owner");
    let owner_id = create_simple_user(&mut conn, &owner_name).await;
    let owner_uuid = get_user_uuid(&mut conn, owner_id).await;
    let admin_id = create_simple_admin_user(&mut conn, &unique_name("term_v14_adm")).await;
    let asset_id = create_simple_ssh_asset(&mut conn, &unique_name("term_v14_ast"), admin_id).await;
    let _ = grant_user_access_to_asset(
        &mut conn,
        owner_id,
        asset_id,
        &unique_name("term_v14_grant"),
        &["ssh"],
    )
    .await;
    let (session_id, session_uuid) =
        create_test_session_with_uuid(&mut conn, owner_id, asset_id, "ssh", "active").await;

    let token = app
        .generate_test_token(&owner_uuid.to_string(), &owner_name, false, false)
        .await;
    let csrf_token = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/api/v1/sessions/{}/terminate", session_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .add_header("X-CSRF-Token", csrf_token.as_str())
        .await;
    assert_status(&response, 200);

    // Recording-finalisation should NOT have happened (no supervisor),
    // BUT the handler must have stamped disconnected_at. The PRIMARY
    // enqueue is therefore wired but a no-op in dev mode -- precisely
    // the documented behaviour.
    use vauban_web::schema::proxy_sessions;
    let (disc_at, fin_at): (
        Option<chrono::DateTime<chrono::Utc>>,
        Option<chrono::DateTime<chrono::Utc>>,
    ) = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::id.eq(session_id))
            .select((
                proxy_sessions::disconnected_at,
                proxy_sessions::recording_finalized_at,
            ))
            .first(&mut conn)
            .await
    );
    assert!(disc_at.is_some(), "disconnected_at stamped");
    assert!(
        fin_at.is_none(),
        "recording_finalized_at stays NULL in dev mode (no supervisor)"
    );
}

// =============================================================================
// Bug fix -- non-HTMX <form method="post"> from the IACS tunnel status
// page (and any other plain form Disconnect button) must NOT dump the
// raw API JSON into the browser address bar. The web wrapper has to
// translate the API outcome into a flash + 303 redirect so the user
// lands back on `/sessions`.
//
// Repro: GET-after-POST showed
//   `{"id":535,"uuid":"…","status":"terminated", … }` in the browser.
// =============================================================================

/// A non-HTMX terminate (no `HX-Request: true`) MUST 303-redirect to
/// `/sessions` on success, NOT return JSON.
#[tokio::test]
async fn test_non_htmx_terminate_redirects_to_sessions_list() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let owner_name = unique_name("term_form_owner");
    let owner_id = create_simple_user(&mut conn, &owner_name).await;
    let owner_uuid = get_user_uuid(&mut conn, owner_id).await;

    let admin_id = create_simple_admin_user(&mut conn, &unique_name("term_form_adm")).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("term_form_ast"), admin_id).await;
    let _ = grant_user_access_to_asset(
        &mut conn,
        owner_id,
        asset_id,
        &unique_name("term_form_grant"),
        &["ssh"],
    )
    .await;
    let (session_id, session_uuid) =
        create_test_session_with_uuid(&mut conn, owner_id, asset_id, "ssh", "active").await;

    let token = app
        .generate_test_token(&owner_uuid.to_string(), &owner_name, false, false)
        .await;
    let csrf_token = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/sessions/{}/terminate", session_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        // INTENTIONALLY no `HX-Request: true` -- this mirrors the
        // plain `<form method="post">` Disconnect button on
        // `/sessions/{uuid}/iacs/status`.
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;

    // axum's `Redirect::to` returns 303 See Other; the location header
    // points at the session list.
    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 302,
        "non-HTMX terminate must 3xx-redirect, got {} (body={:?})",
        status,
        response.text()
    );
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        location.starts_with("/sessions"),
        "redirect must land on the session list, got `{}`",
        location
    );

    // Critical regression assertion: the response body MUST NOT carry
    // the JSON shape that used to leak (id, uuid, session_type, ...)
    // into the user's browser when the form was submitted plain.
    let body = response.text();
    assert!(
        !body.contains("\"session_type\""),
        "non-HTMX terminate response must not echo the API JSON body, got: {}",
        body
    );
    assert!(
        !body.contains("\"client_user_agent\""),
        "non-HTMX terminate response must not echo the API JSON body, got: {}",
        body
    );

    // Side-effect check: the row IS terminated even though we returned
    // a redirect to the user.
    assert_eq!(
        db_status(&mut conn, session_id).await,
        "terminated",
        "non-HTMX terminate must still flip the session row"
    );
}

/// The HTMX path keeps returning the in-place HTML fragment so the
/// `/sessions/active` swap continues to work.
#[tokio::test]
async fn test_htmx_terminate_returns_html_fragment_not_redirect() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let owner_name = unique_name("term_htmx_owner");
    let owner_id = create_simple_user(&mut conn, &owner_name).await;
    let owner_uuid = get_user_uuid(&mut conn, owner_id).await;

    let admin_id = create_simple_admin_user(&mut conn, &unique_name("term_htmx_adm")).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("term_htmx_ast"), admin_id).await;
    let _ = grant_user_access_to_asset(
        &mut conn,
        owner_id,
        asset_id,
        &unique_name("term_htmx_grant"),
        &["ssh"],
    )
    .await;
    let (_, session_uuid) =
        create_test_session_with_uuid(&mut conn, owner_id, asset_id, "ssh", "active").await;

    let token = app
        .generate_test_token(&owner_uuid.to_string(), &owner_name, false, false)
        .await;
    let csrf_token = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/sessions/{}/terminate", session_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .add_header("HX-Request", "true")
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("Session terminated") || body.contains("terminated"),
        "HTMX response must carry the in-place HTML fragment"
    );
    assert!(
        !body.starts_with("{\""),
        "HTMX response must NOT be a JSON body"
    );
}
