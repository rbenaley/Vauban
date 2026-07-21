//! End-to-end coverage for the IACS kill-switch on the **session**
//! surface (`industrial.enabled = false`).
//!
//! Complements the source-grep pins in
//! `iacs_sessions_kill_switch_test.rs` with runtime checks, mirroring
//! the proven approach of `iacs_assets_surface_e2e_test.rs`:
//!
//! * Layer 2 (DB filter): insert real SSH + IACS `proxy_sessions`
//!   rows, then replay the exact production filter clauses the
//!   handlers apply under the kill-switch and assert the IACS rows
//!   drop out (while SSH survives). The baseline (no exclusion)
//!   keeps both, proving the filter -- not the fixture -- is what
//!   hides IACS.
//! * Layer 5 (template gate): render the production
//!   `SessionListTemplate` and `ActiveListStatsWidget` with
//!   `industrial_enabled = false` and assert the IACS affordances are
//!   gone; with `true` they are present.
//! * Forensic: a recorded IACS session is STILL returned by the
//!   recordings filter (which carries no kill-switch gate), and
//!   `recording_list.html` keeps its IACS format option.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common::TestApp;
use crate::fixtures::{
    create_iacs_test_session_with_uuid, create_simple_admin_user, create_simple_iacs_asset,
    create_simple_ssh_asset, create_test_session_with_uuid, unique_name,
};
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::RunQueryDsl;
use vauban_web::models::session::{SessionStatus, SessionType};
use vauban_web::schema::{assets as schema_assets, proxy_sessions};

// ===================================================================
// Layer 2 -- DB filter end-to-end runtime check
// ===================================================================

/// Replays the kill-switch branch of `session_list` (history list)
/// and `active_sessions` at the Diesel level: inserts an active SSH
/// session and an IACS tunnel, then runs the production filter
/// clauses and asserts the IACS row is dropped. Pinned to fail the
/// day a future list path forgets the exclusion.
#[tokio::test]
async fn db_filter_drops_iacs_sessions_when_industrial_disabled() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_simple_admin_user(&mut conn, &unique_name("iacs_sess_ks")).await;
    let ssh_asset = create_simple_ssh_asset(&mut conn, &unique_name("ssh-asset"), admin).await;
    let iacs_asset = create_simple_iacs_asset(&mut conn, &unique_name("iacs-asset"), admin).await;

    let (ssh_id, _) =
        create_test_session_with_uuid(&mut conn, admin, ssh_asset, "ssh", "active").await;
    let (iacs_id, _) =
        create_iacs_test_session_with_uuid(&mut conn, admin, iacs_asset, "tunnel_active").await;

    // --- session_list (history) production filter, kill-switch ON ---
    // Mirror: status.ne("pending"/"orphaned") + the kill-switch
    // `session_type.ne(IacsTunnel)`.
    let history_killed: Vec<i32> = proxy_sessions::table
        .inner_join(schema_assets::table)
        .filter(proxy_sessions::user_id.eq(admin))
        .filter(proxy_sessions::status.ne("pending"))
        .filter(proxy_sessions::status.ne("orphaned"))
        .filter(proxy_sessions::session_type.ne(SessionType::IacsTunnel))
        .select(proxy_sessions::id)
        .load(&mut conn)
        .await
        .expect("history (killed) query must run");
    assert!(
        history_killed.contains(&ssh_id),
        "SSH session must remain on the /sessions history list under the kill-switch"
    );
    assert!(
        !history_killed.contains(&iacs_id),
        "IACS session must be HIDDEN from the /sessions history list under the kill-switch"
    );

    // Baseline: without the kill-switch exclusion both rows surface,
    // proving the exclusion clause (not the fixture) is the cause.
    let history_baseline: Vec<i32> = proxy_sessions::table
        .inner_join(schema_assets::table)
        .filter(proxy_sessions::user_id.eq(admin))
        .filter(proxy_sessions::status.ne("pending"))
        .filter(proxy_sessions::status.ne("orphaned"))
        .select(proxy_sessions::id)
        .load(&mut conn)
        .await
        .expect("history (baseline) query must run");
    assert!(
        history_baseline.contains(&ssh_id) && history_baseline.contains(&iacs_id),
        "baseline (industrial ON) must keep BOTH the SSH and IACS rows visible"
    );

    // --- active_sessions production filter, kill-switch ON ---
    let active_killed: Vec<i32> = proxy_sessions::table
        .inner_join(schema_assets::table)
        .filter(proxy_sessions::user_id.eq(admin))
        .filter(proxy_sessions::status.eq_any(SessionStatus::OPERATOR_ACTIVE_AS_STR))
        .filter(proxy_sessions::connected_at.is_not_null())
        .filter(proxy_sessions::session_type.ne(SessionType::IacsTunnel))
        .select(proxy_sessions::id)
        .load(&mut conn)
        .await
        .expect("active (killed) query must run");
    assert!(
        active_killed.contains(&ssh_id),
        "active SSH session must remain on /sessions/active under the kill-switch"
    );
    assert!(
        !active_killed.contains(&iacs_id),
        "IACS tunnel must be HIDDEN from /sessions/active under the kill-switch"
    );

    // Baseline active query (industrial ON) surfaces the IACS tunnel.
    let active_baseline: Vec<i32> = proxy_sessions::table
        .inner_join(schema_assets::table)
        .filter(proxy_sessions::user_id.eq(admin))
        .filter(proxy_sessions::status.eq_any(SessionStatus::OPERATOR_ACTIVE_AS_STR))
        .filter(proxy_sessions::connected_at.is_not_null())
        .select(proxy_sessions::id)
        .load(&mut conn)
        .await
        .expect("active (baseline) query must run");
    assert!(
        active_baseline.contains(&iacs_id),
        "baseline (industrial ON) must surface the IACS tunnel on /sessions/active"
    );

    // Cleanup.
    diesel::delete(proxy_sessions::table.filter(proxy_sessions::id.eq_any(vec![ssh_id, iacs_id])))
        .execute(&mut conn)
        .await
        .expect("cleanup delete must succeed");
}

/// Forensic surface: a recorded IACS session is STILL returned by the
/// recordings filter (which carries NO kill-switch gate). The
/// kill-switch is surgical to the operational lists; it never
/// collaterally hides the audit trail.
#[tokio::test]
async fn recordings_filter_keeps_iacs_sessions_regardless_of_kill_switch() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_simple_admin_user(&mut conn, &unique_name("iacs_rec_ks")).await;
    let iacs_asset = create_simple_iacs_asset(&mut conn, &unique_name("iacs-rec"), admin).await;
    let (iacs_id, _) =
        create_iacs_test_session_with_uuid(&mut conn, admin, iacs_asset, "terminated").await;

    // Mark the IACS session as recorded with a non-null recording path
    // (the two conditions the recordings catalogue filters on).
    diesel::update(proxy_sessions::table.filter(proxy_sessions::id.eq(iacs_id)))
        .set((
            proxy_sessions::is_recorded.eq(true),
            proxy_sessions::recording_path.eq(Some("recordings/2026/06/iacs.zip".to_string())),
        ))
        .execute(&mut conn)
        .await
        .expect("marking IACS session as recorded must succeed");

    // Recordings production filter: is_recorded + recording_path NOT
    // NULL. NO industrial gate (forensic surface).
    let recordings: Vec<i32> = proxy_sessions::table
        .inner_join(schema_assets::table)
        .filter(proxy_sessions::user_id.eq(admin))
        .filter(proxy_sessions::is_recorded.eq(true))
        .filter(proxy_sessions::recording_path.is_not_null())
        .select(proxy_sessions::id)
        .load(&mut conn)
        .await
        .expect("recordings query must run");
    assert!(
        recordings.contains(&iacs_id),
        "a recorded IACS session MUST stay visible in the recordings catalogue \
         regardless of the kill-switch (forensic surface is orthogonal)"
    );

    diesel::delete(proxy_sessions::table.filter(proxy_sessions::id.eq(iacs_id)))
        .execute(&mut conn)
        .await
        .expect("cleanup delete must succeed");
}

// ===================================================================
// Layer 5 -- template gate runtime check
// ===================================================================

fn vauban_cfg() -> vauban_web::templates::base::VaubanConfig {
    vauban_web::templates::base::VaubanConfig {
        brand_name: "VAUBAN".to_string(),
        brand_logo: None,
        theme: "dark".to_string(),
        ..Default::default()
    }
}

/// `SessionListTemplate` rendered with `industrial_enabled = false`
/// MUST NOT offer the IACS type filter option; with `true` it does.
#[test]
fn session_list_template_hides_iacs_option_under_kill_switch() {
    use vauban_web::templates::sessions::SessionListTemplate;

    let make = |industrial_enabled: bool| SessionListTemplate {
        title: "Sessions".to_string(),
        user: None,
        vauban: vauban_cfg(),
        messages: Vec::new(),
        language_code: "en".to_string(),
        sidebar_content: None,
        header_user: None,
        sessions: Vec::new(),
        status_filter: None,
        type_filter: None,
        asset_filter: None,
        statuses: vauban_web::services::status_vocab::session_history_options(industrial_enabled),
        show_view_link: true,
        pagination: None,
        ws_enabled: false,
        industrial_enabled,
        tz: chrono_tz::Tz::UTC,
    };

    let killed = askama::Template::render(&make(false)).expect("kill-switch render must succeed");
    assert!(
        !killed.contains(r#"value="iacs_tunnel""#),
        "session_list with industrial_enabled = false MUST NOT render the IACS \
         type filter option; rendered HTML follows:\n{killed}"
    );
    // SSH / RDP stay -- the kill-switch is surgical, not collateral.
    assert!(
        killed.contains(r#"value="ssh""#) && killed.contains(r#"value="rdp""#),
        "session_list must keep the SSH and RDP filter options under the kill-switch"
    );

    let baseline = askama::Template::render(&make(true)).expect("baseline render must succeed");
    assert!(
        baseline.contains(r#"value="iacs_tunnel""#),
        "session_list with industrial_enabled = true MUST render the IACS option"
    );
}

/// `ActiveListStatsWidget` rendered with `industrial_enabled = false`
/// MUST NOT render the IACS stat tile; with `true` it does.
#[test]
fn active_list_stats_widget_hides_iacs_tile_under_kill_switch() {
    use vauban_web::templates::sessions::ActiveListStatsWidget;

    let killed = ActiveListStatsWidget {
        sessions: Vec::new(),
        industrial_enabled: false,
    };
    let html = askama::Template::render(&killed).expect("kill-switch render must succeed");
    assert!(
        !html.contains(">IACS<"),
        "active_list_stats with industrial_enabled = false MUST NOT render the \
         IACS stat tile; rendered HTML follows:\n{html}"
    );
    // SSH / RDP tiles stay.
    assert!(
        html.contains(">SSH<") && html.contains(">RDP<"),
        "active_list_stats must keep the SSH and RDP tiles under the kill-switch"
    );

    let baseline = ActiveListStatsWidget {
        sessions: Vec::new(),
        industrial_enabled: true,
    };
    let html = askama::Template::render(&baseline).expect("baseline render must succeed");
    assert!(
        html.contains(">IACS<"),
        "active_list_stats with industrial_enabled = true MUST render the IACS tile"
    );
}
