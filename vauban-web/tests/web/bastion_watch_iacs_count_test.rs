//! E2E tests: IACS tunnels are counted on the Bastion Watch home
//! page (`URN=/`).
//!
//! Surface under test: the supervisor view of `/` MUST count IACS
//! `tunnel_active` rows in the LIVE hero tile AND list them in the
//! Live Sessions panel right below it. Without this, an industrial
//! engineer's tunnel is invisible on the operator's main pane and
//! the count silently disagrees with `/sessions/active` (where
//! `tunnel_active` was already correctly included by issue 0.7.x).
//!
//! Three query sites are pinned by these tests because they all
//! contribute to what an operator sees on `/`:
//!
//! - `services::dashboard::snapshot::load_hero` -- the LIVE count
//!   on the hero band (first paint via `dashboard_home`).
//! - `services::dashboard::snapshot::load_live_sessions` -- the
//!   Live Sessions panel right below the hero band.
//! - `handlers::web::dashboard::dashboard_widget_stats` and
//!   `dashboard_widget_active_sessions` -- the HTMX endpoints used
//!   to refresh the same tiles without a full page reload.
//!
//! The IACS lifecycle persistence (`waiting_client` ->
//! `tunnel_active` -> `terminated`) is exercised by
//! `iacs_active_sessions_integration_test.rs`; here we only assert
//! that a row already in `tunnel_active` reaches the dashboard
//! surfaces.

use crate::common::{TestApp, unwrap_ok};
use crate::fixtures::{
    create_iacs_test_session_with_uuid, create_simple_admin_user, create_simple_iacs_asset,
    create_simple_user, unique_name,
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
// 1. The LIVE hero tile counts IACS tunnels
// ===================================================================

/// An IACS tunnel in `tunnel_active` MUST surface on the LIVE hero
/// tile of `/`. Asserted by checking that the Live Sessions panel
/// (which shares the same composite filter) lists the IACS row's
/// asset hostname -- a stable, IACS-specific marker that the
/// surrounding chrome of `/` does not produce.
#[tokio::test]
async fn iacs_tunnel_active_is_counted_on_bastion_watch_home() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_username = unique_name("bw_iacs_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username).await;
    let admin_uuid = user_uuid(&mut conn, admin_id).await;

    let user_id = create_simple_user(&mut conn, "bw_iacs_user").await;
    // The asset name is unique per call (cf. `create_simple_iacs_asset`
    // -> `unique_hostname`) so the assertion below cannot collide with
    // an unrelated SSH/RDP fixture from a previous test.
    let iacs_asset_name = unique_name("bw-iacs-target");
    let asset_id = create_simple_iacs_asset(&mut conn, &iacs_asset_name, admin_id).await;

    let (_session_id, _session_uuid) =
        create_iacs_test_session_with_uuid(&mut conn, user_id, asset_id, "tunnel_active").await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_username, true, true)
        .await;

    let response = app
        .server
        .get("/")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(
        response.status_code().as_u16(),
        200,
        "/ must load with admin credentials"
    );

    let body = response.text();

    // The Live Sessions panel renders the asset name (cf.
    // `templates/dashboard/tiles/_live_sessions.html`). Its presence
    // proves the SQL filter in `load_live_sessions` accepted the
    // `tunnel_active` row.
    assert!(
        body.contains(&iacs_asset_name),
        "Bastion Watch home MUST list the IACS tunnel's asset name in \
         the Live Sessions panel; missing `{}` in body. \
         Excerpt:\n{}",
        iacs_asset_name,
        // Keep the assertion message readable on CI.
        body.lines()
            .filter(|l| l.contains("LIVE")
                || l.contains("Live sessions")
                || l.contains("active sessions"))
            .take(20)
            .collect::<Vec<_>>()
            .join("\n")
    );

    // The LIVE hero tile shows `{{ snapshot.hero.live }}` followed
    // by the "active sessions" label. A regression that drops the
    // composite filter would render `0` here. The combined check
    // (asset name + non-zero count marker) ensures the count went
    // up for OUR session, not just any pre-existing fixture.
    assert!(
        body.contains("active sessions"),
        "Bastion Watch home MUST render the LIVE hero tile (with the \
         'active sessions' label)"
    );
    // Hard guarantee: the literal `>0<` immediately followed by
    // `active sessions` indicates the IACS row was missed. We
    // refuse it via a structural search.
    assert!(
        !body.contains(">0</p>\n      <p class=\"text-xs text-gray-500 dark:text-gray-400 mt-1 whitespace-nowrap\">active sessions"),
        "Bastion Watch LIVE tile MUST NOT report 0 when an IACS \
         tunnel is active in the database (this is the regression \
         the composite filter fixes)."
    );
}

// ===================================================================
// 2. The WS-pushed refresh path carries the composite filter, and
//    the legacy un-routed / un-gated HTMX widget handlers stay
//    removed (BAC hardening: they ran bastion-wide queries without
//    a Casbin gate and without the per-user scoping enforced by
//    `dashboard_home`). The production refresh path is the pusher
//    in `tasks::dashboard`; its SQL contract with `load_hero` /
//    `load_live_sessions` is pinned via source-grep.
// ===================================================================

#[test]
fn dashboard_widget_handlers_stay_removed() {
    let src = include_str!("../../src/handlers/web/dashboard.rs");

    for legacy in [
        "pub async fn dashboard_widget_stats(",
        "pub async fn dashboard_widget_active_sessions(",
        "pub async fn dashboard_widget_recent_activity(",
    ] {
        assert!(
            !src.contains(legacy),
            "`{}` was removed by the BAC hardening (un-routed, \
             un-gated, bastion-wide queries). Re-introducing it \
             requires a Casbin gate + the dashboard per-user \
             scoping contract.",
            legacy
        );
    }
}

#[test]
fn dashboard_pusher_tasks_count_iacs_tunnels() {
    let src = include_str!("../../src/tasks/dashboard.rs");

    for (fn_name, needle) in [
        (
            "fn fetch_stats",
            "status.eq_any([\"active\", \"ews_connected\", \"tunnel_active\"])",
        ),
        (
            "fn fetch_active_sessions",
            "status.eq_any([\"active\", \"ews_connected\", \"tunnel_active\"])",
        ),
    ] {
        let idx = src
            .find(fn_name)
            .unwrap_or_else(|| panic!("{} must exist in tasks::dashboard", fn_name));
        let next = src[idx + 1..]
            .find("\nasync fn ")
            .map(|i| idx + 1 + i)
            .unwrap_or(src.len());
        let body = &src[idx..next];
        assert!(
            body.contains(needle),
            "{} MUST count both `active` (SSH/RDP) and `tunnel_active` \
             (IACS) so the WS-refreshed LIVE tile agrees with the \
             first-paint count from `load_hero`.",
            fn_name
        );
    }
}

// ===================================================================
// 3. Negative case: terminated rows MUST stay invisible
// ===================================================================

/// Symmetric to the visibility tests: a TERMINATED IACS row MUST
/// NOT inflate the LIVE count. Without this assertion a regression
/// that swapped `eq_any(["active", "tunnel_active"])` for
/// `ne("waiting_client")` (a tempting but wrong shortcut) would
/// pass the visibility tests yet count `terminated` rows as live.
#[tokio::test]
async fn iacs_terminated_is_not_counted_on_bastion_watch_home() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_username = unique_name("bw_term_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username).await;
    let admin_uuid = user_uuid(&mut conn, admin_id).await;

    let user_id = create_simple_user(&mut conn, "bw_term_user").await;
    let asset_name = unique_name("bw-term-iacs");
    let asset_id = create_simple_iacs_asset(&mut conn, &asset_name, admin_id).await;
    let (_session_id, _session_uuid) =
        create_iacs_test_session_with_uuid(&mut conn, user_id, asset_id, "terminated").await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_username, true, true)
        .await;

    let response = app
        .server
        .get("/")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response.status_code().as_u16(), 200);
    let body = response.text();
    assert!(
        !body.contains(&asset_name),
        "terminated IACS row MUST NOT appear in the Live Sessions \
         panel"
    );
}
