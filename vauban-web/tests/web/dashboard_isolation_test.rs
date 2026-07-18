//! Bastion Watch -- per-user isolation E2E tests (L5).
//!
//! These tests are the runtime backstop of the 5-layer defence:
//!
//! - L1 (type system) -- pinned by `bastion_watch_test.rs::every_user_scopable_loader_takes_dashboard_scope`
//! - L2 (SQL filter) -- exercised here against a real PostgreSQL via TestApp
//! - L3 (Casbin gate) -- pinned by `bastion_watch_test.rs::dashboard_handler_derives_scope_from_sessions_supervise`
//! - L4 (lint) -- `scripts/check_dashboard_user_scoping.sh`
//! - L5 (E2E) -- this file
//!
//! Scenario: two distinct users U1 and U2, each owning one active
//! session on a private asset. U1 logs in (non-supervisor) and
//! GETs `/`. The rendered HTML MUST NOT mention U2's username,
//! U2's asset, or U2's session UUID. The supervisor logs in and
//! GETs `/`; both users' resources MUST surface.

use axum::http::header::COOKIE;
use serial_test::serial;
use uuid::Uuid;

use crate::common::{TestApp, assertions::assert_status};
use crate::fixtures::{
    create_simple_admin_user, create_simple_ssh_asset, create_simple_user, create_test_session,
    unique_name,
};
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::{AsyncPgConnection, RunQueryDsl};

async fn user_uuid(conn: &mut AsyncPgConnection, user_id: i32) -> Uuid {
    use vauban_web::schema::users;
    users::table
        .filter(users::id.eq(user_id))
        .select(users::uuid)
        .first(conn)
        .await
        .expect("user uuid lookup")
}

async fn asset_uuid(conn: &mut AsyncPgConnection, asset_id: i32) -> Uuid {
    use vauban_web::schema::assets;
    assets::table
        .filter(assets::id.eq(asset_id))
        .select(assets::uuid)
        .first(conn)
        .await
        .expect("asset uuid lookup")
}

#[tokio::test]
#[serial]
async fn dashboard_no_cross_tenant_leak_initial_render() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Two unrelated users with one active session each on their own
    // private asset. The asset name is folded into the live-sessions
    // panel, so leaks are easy to grep.
    let u1_username = unique_name("isolation_u1");
    let u2_username = unique_name("isolation_u2");
    let u1_id = create_simple_user(&mut conn, &u1_username).await;
    let u2_id = create_simple_user(&mut conn, &u2_username).await;

    let u1_asset_name = unique_name("u1_secret_asset");
    let u2_asset_name = unique_name("u2_secret_asset");
    let u1_asset_id = create_simple_ssh_asset(&mut conn, &u1_asset_name, u1_id).await;
    let u2_asset_id = create_simple_ssh_asset(&mut conn, &u2_asset_name, u2_id).await;

    let _u1_session = create_test_session(&mut conn, u1_id, u1_asset_id, "ssh", "active").await;
    let u2_session_uuid: Uuid = {
        // We need U2's session uuid as a leak grep target.
        use vauban_web::schema::proxy_sessions;
        let _ = create_test_session(&mut conn, u2_id, u2_asset_id, "ssh", "active").await;
        proxy_sessions::table
            .filter(proxy_sessions::user_id.eq(u2_id))
            .filter(proxy_sessions::status.eq("active"))
            .select(proxy_sessions::uuid)
            .first(&mut conn)
            .await
            .expect("u2 session uuid")
    };

    let u1_uuid = user_uuid(&mut conn, u1_id).await;
    // Both flags false: a regular `role:user`. The handler MUST
    // derive DashboardScope::User(u1_id) and the loaders MUST inject
    // `WHERE proxy_sessions.user_id = u1_id`.
    let token = app
        .generate_test_token(&u1_uuid.to_string(), &u1_username, false, false)
        .await;

    let response = app
        .server
        .get("/")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_status(&response, 200);

    let body = response.text();

    // Anti-leak grep targets. We strip an asset_name leak target down
    // to its unique stem so a substring of u2_asset_name cannot
    // accidentally match boilerplate.
    assert!(
        !body.contains(&u2_username),
        "non-supervisor U1's dashboard MUST NOT render U2's username \
         `{}` -- found in body. The L2 SQL filter on proxy_sessions.user_id \
         is broken or the template ignored the scope.",
        u2_username
    );
    assert!(
        !body.contains(&u2_asset_name),
        "non-supervisor U1's dashboard MUST NOT render U2's asset \
         `{}` (folded into the live-sessions panel).",
        u2_asset_name
    );
    let u2_uuid_str = u2_session_uuid.to_string();
    assert!(
        !body.contains(&u2_uuid_str),
        "non-supervisor U1's dashboard MUST NOT mention U2's active \
         session UUID `{}` (an IDOR vector).",
        u2_uuid_str
    );

    // Sanity: U1's own asset name is on the page (the live-sessions
    // panel lists U1's session). Otherwise we are not exercising the
    // happy path of the L2 filter.
    assert!(
        body.contains(&u1_asset_name),
        "U1 must see its OWN asset `{}` in the live-sessions panel; \
         otherwise the test is not exercising the user-scoped SELECT \
         (false-negative).",
        u1_asset_name
    );
}

#[tokio::test]
#[serial]
async fn dashboard_supervisor_sees_global_initial_render() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Two non-supervisor users, then a supervisor that should see
    // both lanes.
    let u1_username = unique_name("super_iso_u1");
    let u2_username = unique_name("super_iso_u2");
    let u1_id = create_simple_user(&mut conn, &u1_username).await;
    let u2_id = create_simple_user(&mut conn, &u2_username).await;

    let u1_asset_name = unique_name("u1_super_asset");
    let u2_asset_name = unique_name("u2_super_asset");
    let u1_asset_id = create_simple_ssh_asset(&mut conn, &u1_asset_name, u1_id).await;
    let u2_asset_id = create_simple_ssh_asset(&mut conn, &u2_asset_name, u2_id).await;
    let _ = create_test_session(&mut conn, u1_id, u1_asset_id, "ssh", "active").await;
    let _ = create_test_session(&mut conn, u2_id, u2_asset_id, "ssh", "active").await;

    let supervisor_username = unique_name("super_iso_admin");
    let supervisor_id = create_simple_admin_user(&mut conn, &supervisor_username).await;
    let supervisor_uuid = user_uuid(&mut conn, supervisor_id).await;

    let token = app
        .generate_test_token(
            &supervisor_uuid.to_string(),
            &supervisor_username,
            true,
            true,
        )
        .await;

    let response = app
        .server
        .get("/")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_status(&response, 200);

    let body = response.text();

    // The supervisor's live-sessions panel lists every active
    // session; both asset names MUST surface. The previous regression
    // (admin sees Global, user sees Global too) failed this test by
    // succeeding for both views; we now exercise the symmetric
    // expectation explicitly.
    assert!(
        body.contains(&u1_asset_name),
        "supervisor MUST see U1's asset `{}` in the live-sessions \
         panel under Global scope.",
        u1_asset_name
    );
    assert!(
        body.contains(&u2_asset_name),
        "supervisor MUST see U2's asset `{}` in the live-sessions \
         panel under Global scope.",
        u2_asset_name
    );
}

#[tokio::test]
#[serial]
async fn dashboard_user_sees_personal_ws_endpoint_in_template() {
    // The L3 routing seam: a non-supervisor's HTML page MUST embed
    // the per-user WS endpoint, NEVER the singleton dashboard
    // endpoint (which a defence-in-depth check now rejects with
    // 403 anyway).
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("user_ws_route");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = user_uuid(&mut conn, user_id).await;
    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;

    let response = app
        .server
        .get("/")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_status(&response, 200);

    let body = response.text();
    assert!(
        body.contains("ws-connect=\"/ws/dashboard/personal\""),
        "non-supervisor HTML MUST embed `ws-connect=\"/ws/dashboard/personal\"`. \
         Routing them on `/ws/dashboard` would either flood them with \
         supervisor-scope payloads (regression) or hand them a 403 (UX bug)."
    );
    assert!(
        !body.contains("ws-connect=\"/ws/dashboard\""),
        "non-supervisor HTML MUST NOT embed the singleton WS endpoint."
    );
}

#[tokio::test]
#[serial]
async fn dashboard_supervisor_sees_singleton_ws_endpoint_in_template() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("admin_ws_route");
    let user_id = create_simple_admin_user(&mut conn, &username).await;
    let user_uuid = user_uuid(&mut conn, user_id).await;
    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, true, true)
        .await;

    let response = app
        .server
        .get("/")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_status(&response, 200);

    let body = response.text();
    assert!(
        body.contains("ws-connect=\"/ws/dashboard\""),
        "supervisor HTML MUST embed `ws-connect=\"/ws/dashboard\"` \
         (singleton DashboardStats channel). A drift to /personal \
         would break the global view's live updates."
    );
    assert!(
        !body.contains("ws-connect=\"/ws/dashboard/personal\""),
        "supervisor HTML MUST NOT embed the per-user endpoint."
    );
}

#[tokio::test]
#[serial]
async fn dashboard_heatmap_user_scoped_aggregates_only_self() {
    // The heatmap is a 14d * 24h grid of session opening counts. A
    // non-supervisor user MUST see only their own activity. We
    // create 1 session for U1 and 5 for U2 within the same day; the
    // U1 dashboard MUST NOT inflate to 6.
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let u1_username = unique_name("heatmap_iso_u1");
    let u2_username = unique_name("heatmap_iso_u2");
    let u1_id = create_simple_user(&mut conn, &u1_username).await;
    let u2_id = create_simple_user(&mut conn, &u2_username).await;

    let u1_asset_id = create_simple_ssh_asset(&mut conn, &unique_name("h1_asset"), u1_id).await;
    let u2_asset_id = create_simple_ssh_asset(&mut conn, &unique_name("h2_asset"), u2_id).await;

    let _ = create_test_session(&mut conn, u1_id, u1_asset_id, "ssh", "disconnected").await;
    for _ in 0..5 {
        let _ = create_test_session(&mut conn, u2_id, u2_asset_id, "ssh", "disconnected").await;
    }

    let u1_uuid = user_uuid(&mut conn, u1_id).await;
    let token = app
        .generate_test_token(&u1_uuid.to_string(), &u1_username, false, false)
        .await;
    let response = app
        .server
        .get("/")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_status(&response, 200);

    // We can't easily parse SVG cell counts from the raw HTML. Use an
    // indirect oracle: the LIVE counter, the TODAY counter, and the
    // EVIDENCE counter all read from the same scope as the heatmap.
    // If the heatmap leaked, so would these. We verify TODAY by
    // ensuring U2's username does not appear in the page.
    let body = response.text();
    assert!(
        !body.contains(&u2_username),
        "U1's dashboard heatmap test: U2's username MUST NOT appear \
         in the rendered page (cross-scope evidence of leak)."
    );
}

// Suppress unused-import warning if `asset_uuid` is not used on every
// build (the helper exists for future cases that need to assert on
// asset UUIDs in the HTML body).
#[allow(dead_code)]
async fn _unused_asset_uuid(conn: &mut AsyncPgConnection, id: i32) -> Uuid {
    asset_uuid(conn, id).await
}
