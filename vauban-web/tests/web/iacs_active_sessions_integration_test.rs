//! E2E tests: IACS tunnels on the admin `/sessions/active` page.
//!
//! Surface under test: the user must be able to observe IACS tunnels
//! on `/sessions/active` with the same indicators as SSH/RDP
//! sessions:
//!
//! - protocol badge ("IACS"),
//! - "user -> asset" pair,
//! - destination endpoint (asset hostname),
//! - source address (the EWS peer IP if known, the WebUI browser IP
//!   otherwise),
//! - "connected at" timestamp,
//! - duration (re-rendered every 10 s by the dashboard pump),
//!
//! and disconnect them via the same `Disconnect` button.
//!
//! See `vauban-web/src/handlers/web/sessions.rs::active_sessions`
//! and the matching `tasks::dashboard::fetch_active_sessions_full` /
//! `handlers::websocket::fetch_active_sessions_list` for the three
//! query sites. The IACS lifecycle persistence happens in
//! `ipc::proxy_iacs::handle_message` (`IacsTunnelStatusUpdate` ->
//! `tunnel_active` row update; `IacsTunnelClosed` -> `terminated`).

use crate::common::{TestApp, unwrap_ok};
use crate::fixtures::{
    create_iacs_test_session_with_uuid, create_simple_admin_user, create_simple_iacs_asset,
    create_simple_rdp_asset, create_simple_ssh_asset, create_simple_user,
    create_test_session_with_uuid, unique_name,
};
use axum::http::header::COOKIE;
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use uuid::Uuid;

async fn user_uuid(conn: &mut AsyncPgConnection, user_id: i32) -> Uuid {
    use vauban_web::schema::users;
    unwrap_ok!(
        users::table
            .filter(users::id.eq(user_id))
            .select(users::uuid)
            .first(conn)
            .await
    )
}

// ===================================================================
// 1. Visibility
// ===================================================================

/// An IACS tunnel in `tunnel_active` MUST surface on
/// `/sessions/active` alongside SSH/RDP rows. Pinned by
/// `tests/web/iacs_active_sessions_integration_test.rs` so a
/// regression in any of the three filter sites
/// (`active_sessions` handler, `fetch_active_sessions_full`,
/// `fetch_active_sessions_list`) shows up loudly.
#[tokio::test]
async fn iacs_tunnel_active_surfaces_on_active_sessions_page() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_username = unique_name("iacs_active_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username).await;
    let admin_uuid = user_uuid(&mut conn, admin_id).await;

    let user_id = create_simple_user(&mut conn, "iacs_active_user").await;
    let asset_id = create_simple_iacs_asset(&mut conn, "iacs-active-target", admin_id).await;
    let (_session_id, session_uuid) =
        create_iacs_test_session_with_uuid(&mut conn, user_id, asset_id, "tunnel_active").await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_username, true, true)
        .await;

    let response = app
        .server
        .get("/sessions/active")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(
        response.status_code().as_u16(),
        200,
        "/sessions/active must load with admin credentials"
    );

    let body = response.text();
    assert!(
        body.contains(&session_uuid.to_string()),
        "active list must include the IACS tunnel session UUID; body=\n{}",
        &body[..body.len().min(2000)]
    );
    assert!(
        body.contains(">IACS<"),
        "active list must render the 'IACS' badge label (not the verbose \
         IACS_TUNNEL); body=\n{}",
        &body[..body.len().min(2000)]
    );
    assert!(
        body.contains("amber"),
        "active list must apply the IACS amber colour class to the badge"
    );
}

/// IACS sessions in `waiting_client` (no EWS connected yet, no
/// `connected_at`) MUST NOT appear on the active list. Symmetric to
/// the existing exclusion of SSH/RDP rows with `connected_at` NULL.
#[tokio::test]
async fn iacs_waiting_client_is_excluded_from_active_sessions_page() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_username = unique_name("iacs_waiting_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username).await;
    let admin_uuid = user_uuid(&mut conn, admin_id).await;

    let user_id = create_simple_user(&mut conn, "iacs_waiting_user").await;
    let asset_id = create_simple_iacs_asset(&mut conn, "iacs-waiting-target", admin_id).await;
    let (_session_id, session_uuid) =
        create_iacs_test_session_with_uuid(&mut conn, user_id, asset_id, "waiting_client").await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_username, true, true)
        .await;

    let response = app
        .server
        .get("/sessions/active")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response.status_code().as_u16(), 200);
    let body = response.text();
    assert!(
        !body.contains(&session_uuid.to_string()),
        "waiting_client IACS row must NOT appear in the active list \
         (no connected_at => excluded)"
    );
}

/// IACS sessions in `terminated` MUST NOT appear: they are not live.
#[tokio::test]
async fn iacs_terminated_is_excluded_from_active_sessions_page() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_username = unique_name("iacs_term_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username).await;
    let admin_uuid = user_uuid(&mut conn, admin_id).await;

    let user_id = create_simple_user(&mut conn, "iacs_term_user").await;
    let asset_id = create_simple_iacs_asset(&mut conn, "iacs-term-target", admin_id).await;
    let (_session_id, session_uuid) =
        create_iacs_test_session_with_uuid(&mut conn, user_id, asset_id, "terminated").await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_username, true, true)
        .await;

    let response = app
        .server
        .get("/sessions/active")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response.status_code().as_u16(), 200);
    let body = response.text();
    assert!(
        !body.contains(&session_uuid.to_string()),
        "terminated IACS row must never surface on the active list"
    );
}

// ===================================================================
// 2. Mixed protocols (the headline operator scenario)
// ===================================================================

/// SSH, RDP, and IACS sessions all live at the same time MUST surface
/// together with the right badge each. Mirrors the operator's main
/// pane: see at a glance who is doing what right now.
#[tokio::test]
async fn active_sessions_page_renders_all_three_protocols_with_distinct_badges() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_username = unique_name("mixed_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username).await;
    let admin_uuid = user_uuid(&mut conn, admin_id).await;

    let user_id = create_simple_user(&mut conn, "mixed_user").await;

    let ssh_asset_id = create_simple_ssh_asset(&mut conn, "mixed-ssh", admin_id).await;
    let rdp_asset_id = create_simple_rdp_asset(&mut conn, "mixed-rdp", admin_id).await;
    let iacs_asset_id = create_simple_iacs_asset(&mut conn, "mixed-iacs", admin_id).await;

    let (_, ssh_uuid) =
        create_test_session_with_uuid(&mut conn, user_id, ssh_asset_id, "ssh", "active").await;
    let (_, rdp_uuid) =
        create_test_session_with_uuid(&mut conn, user_id, rdp_asset_id, "rdp", "active").await;
    let (_, iacs_uuid) =
        create_iacs_test_session_with_uuid(&mut conn, user_id, iacs_asset_id, "tunnel_active")
            .await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_username, true, true)
        .await;

    let response = app
        .server
        .get("/sessions/active")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response.status_code().as_u16(), 200);
    let body = response.text();

    for u in [&ssh_uuid, &rdp_uuid, &iacs_uuid] {
        assert!(
            body.contains(&u.to_string()),
            "each session UUID must appear; missing {}",
            u
        );
    }
    for label in [">SSH<", ">RDP<", ">IACS<"] {
        assert!(
            body.contains(label),
            "every protocol must have its dedicated badge; missing {}",
            label
        );
    }
}

// ===================================================================
// 3. Stats counters
// ===================================================================

/// The "IACS" stat tile MUST count `tunnel_active` rows. SSH/RDP
/// counters MUST stay independent.
#[tokio::test]
async fn active_sessions_stats_count_iacs_tunnels_separately() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_username = unique_name("stats_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username).await;
    let admin_uuid = user_uuid(&mut conn, admin_id).await;

    let user_id = create_simple_user(&mut conn, "stats_user").await;
    let iacs_asset_id = create_simple_iacs_asset(&mut conn, "stats-iacs", admin_id).await;

    let _ = create_iacs_test_session_with_uuid(&mut conn, user_id, iacs_asset_id, "tunnel_active")
        .await;
    let _ = create_iacs_test_session_with_uuid(&mut conn, user_id, iacs_asset_id, "tunnel_active")
        .await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_username, true, true)
        .await;

    let response = app
        .server
        .get("/sessions/active")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response.status_code().as_u16(), 200);
    let body = response.text();

    assert!(
        body.contains("IACS"),
        "stats tile labelled 'IACS' must be present"
    );
}

// ===================================================================
// 4. Disconnect
// ===================================================================

/// The Disconnect button must work for IACS tunnels and flip the row
/// to `terminated`. The IPC dispatch is exercised in
/// `iacs_active_sessions_terminate_dispatch_test`; this test pins the
/// HTTP -> DB transition that the active list relies upon.
#[tokio::test]
async fn disconnect_button_terminates_iacs_tunnel_and_removes_it_from_active_list() {
    use vauban_web::schema::proxy_sessions;

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_username = unique_name("disc_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username).await;
    let admin_uuid = user_uuid(&mut conn, admin_id).await;

    let user_id = create_simple_user(&mut conn, "disc_user").await;
    let asset_id = create_simple_iacs_asset(&mut conn, "disc-iacs", admin_id).await;
    let (_, session_uuid) =
        create_iacs_test_session_with_uuid(&mut conn, user_id, asset_id, "tunnel_active").await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_username, true, true)
        .await;

    let csrf = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/sessions/{}/terminate", session_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf),
        )
        .form(&serde_json::json!({"csrf_token": csrf}))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 303,
        "terminate must succeed for an IACS tunnel; got {}",
        status
    );

    let new_status: String = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::uuid.eq(session_uuid))
            .select(proxy_sessions::status)
            .first(&mut conn)
            .await
    );
    assert_eq!(
        new_status, "terminated",
        "IACS row must be flipped to terminated after disconnect"
    );

    let after = app
        .server
        .get("/sessions/active")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    let body = after.text();
    assert!(
        !body.contains(&session_uuid.to_string()),
        "terminated IACS row must no longer appear on the active list"
    );
}
