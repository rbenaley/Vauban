//! Recording retention reaper integration tests (DB selection + metadata clear).

use crate::common::TestApp;
use crate::fixtures::{
    create_recorded_session_with_type, create_simple_admin_user, create_simple_ssh_asset,
    unique_name,
};
use chrono::{Duration, Utc};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use uuid::Uuid;
use vauban_web::schema::proxy_sessions::dsl;
use vauban_web::services::recording_reaper::{
    clear_recording_metadata, select_age_candidates, select_quota_candidates,
    total_finalized_bytes, TASK_NAME,
};

async fn insert_recorded_session(
    conn: &mut diesel_async::AsyncPgConnection,
    user_id: i32,
    asset_id: i32,
    disconnected_at: chrono::DateTime<Utc>,
    status: &str,
    size_bytes: Option<i64>,
) -> (i32, Uuid) {
    let session_uuid = Uuid::new_v4();
    let recording_path = format!("recordings/2024/01/{session_uuid}/");
    let ip: ipnetwork::IpNetwork = "127.0.0.1".parse().unwrap();
    let id: i32 = diesel::insert_into(dsl::proxy_sessions)
        .values((
            dsl::uuid.eq(session_uuid),
            dsl::user_id.eq(user_id),
            dsl::asset_id.eq(asset_id),
            dsl::credential_id.eq("cred-retention"),
            dsl::credential_username.eq("testuser"),
            dsl::session_type.eq(vauban_web::models::session::SessionType::Ssh),
            dsl::status.eq(status),
            dsl::client_ip.eq(ip),
            dsl::connected_at.eq(disconnected_at - Duration::hours(1)),
            dsl::disconnected_at.eq(disconnected_at),
            dsl::is_recorded.eq(true),
            dsl::recording_path.eq(&recording_path),
            dsl::recording_size_bytes.eq(size_bytes),
            dsl::recording_finalized_at.eq(size_bytes.map(|_| Utc::now())),
            dsl::metadata.eq(serde_json::json!({})),
        ))
        .returning(dsl::id)
        .get_result(conn)
        .await
        .expect("insert recorded session");
    (id, session_uuid)
}

#[tokio::test]
async fn age_candidates_select_only_sessions_older_than_cutoff() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin_id = create_simple_admin_user(&mut conn, &unique_name("reap-admin")).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("reap-asset"), admin_id).await;

    let (_, old_uuid) = insert_recorded_session(
        &mut conn,
        admin_id,
        asset_id,
        Utc::now() - Duration::days(5000),
        "completed",
        None,
    )
    .await;

    let (_, recent_uuid) = insert_recorded_session(
        &mut conn,
        admin_id,
        asset_id,
        Utc::now() - Duration::days(10),
        "completed",
        None,
    )
    .await;

    let cutoff = Utc::now() - Duration::days(365);
    let candidates = select_age_candidates(&mut conn, cutoff, 50)
        .await
        .expect("select age");
    assert!(
        candidates
            .iter()
            .any(|(_, u, _, _)| *u == old_uuid),
        "old session must be an age candidate"
    );
    assert!(
        !candidates
            .iter()
            .any(|(_, u, _, _)| *u == recent_uuid),
        "recent session must not be an age candidate"
    );
}

#[tokio::test]
async fn age_candidates_skip_active_sessions() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin_id = create_simple_admin_user(&mut conn, &unique_name("reap-active")).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("reap-asset2"), admin_id).await;

    let (_, uuid) = insert_recorded_session(
        &mut conn,
        admin_id,
        asset_id,
        Utc::now() - Duration::days(5000),
        "active",
        None,
    )
    .await;

    let cutoff = Utc::now() - Duration::days(365);
    let candidates = select_age_candidates(&mut conn, cutoff, 50)
        .await
        .expect("select age");
    assert!(
        !candidates.iter().any(|(_, u, _, _)| *u == uuid),
        "active session must never be reaped"
    );
}

#[tokio::test]
async fn quota_candidates_ordered_fifo_and_require_finalized_size() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin_id = create_simple_admin_user(&mut conn, &unique_name("reap-quota")).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("reap-asset3"), admin_id).await;

    let (_, u1) = insert_recorded_session(
        &mut conn,
        admin_id,
        asset_id,
        Utc::now() - Duration::days(5),
        "completed",
        Some(500_000_000),
    )
    .await;
    let (_, u2) = insert_recorded_session(
        &mut conn,
        admin_id,
        asset_id,
        Utc::now() - Duration::days(2),
        "completed",
        Some(600_000_000),
    )
    .await;

    let total = total_finalized_bytes(&mut conn).await.expect("total");
    assert!(total >= 1_000_000_000);

    let candidates = select_quota_candidates(&mut conn, 100)
        .await
        .expect("quota select");
    let pos1 = candidates
        .iter()
        .position(|(_, u, _, _)| *u == u1)
        .expect("u1 must be a quota candidate");
    let pos2 = candidates
        .iter()
        .position(|(_, u, _, _)| *u == u2)
        .expect("u2 must be a quota candidate");
    assert!(
        pos1 < pos2,
        "oldest disconnected_at first (FIFO): u1 before u2"
    );
}

#[tokio::test]
async fn clear_recording_metadata_nulls_all_recording_columns() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin_id = create_simple_admin_user(&mut conn, &unique_name("reap-clear")).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("reap-asset4"), admin_id).await;
    let session_id =
        create_recorded_session_with_type(&mut conn, admin_id, asset_id, "ssh").await;

    diesel::update(dsl::proxy_sessions.filter(dsl::id.eq(session_id)))
        .set((
            dsl::recording_blake3
                .eq("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
            dsl::recording_size_bytes.eq(100_i64),
            dsl::recording_finalized_at.eq(Utc::now()),
        ))
        .execute(&mut conn)
        .await
        .expect("fill integrity");

    let updated = clear_recording_metadata(&mut conn, session_id)
        .await
        .expect("clear");
    assert_eq!(updated, 1);

    let row: (
        bool,
        Option<String>,
        Option<i64>,
        Option<chrono::DateTime<Utc>>,
    ) = dsl::proxy_sessions
        .filter(dsl::id.eq(session_id))
        .select((
            dsl::is_recorded,
            dsl::recording_path,
            dsl::recording_size_bytes,
            dsl::recording_finalized_at,
        ))
        .first(&mut conn)
        .await
        .expect("reload row");

    assert!(!row.0);
    assert!(row.1.is_none());
    assert!(row.2.is_none());
    assert!(row.3.is_none());
}

#[test]
fn retention_not_exposed_via_http_routes() {
    let main_rs = include_str!("../../src/main.rs");
    for line in main_rs.lines() {
        if line.contains(".route(") && line.contains("retention") {
            panic!("retention must not be exposed via HTTP routes: {line}");
        }
    }
    let api_sessions = include_str!("../../src/handlers/api/sessions.rs");
    assert!(
        !api_sessions.contains("retention_"),
        "API sessions handler must not reference retention config"
    );
}

#[test]
fn retention_bootstrap_started_from_main_when_enabled() {
    let main_rs = include_str!("../../src/main.rs");
    assert!(
        main_rs.contains("run_bootstrap_retention"),
        "main.rs must run bootstrap retention at boot"
    );
    assert!(
        main_rs.contains("start_recording_retention"),
        "main.rs must start the recording retention daily cron"
    );
    assert!(
        main_rs.contains("retention_enabled"),
        "main.rs must gate retention on config.recording.retention_enabled"
    );
}

#[test]
fn handlers_do_not_delete_recordings_directly() {
    let sessions = include_str!("../../src/handlers/web/sessions.rs");
    assert!(
        !sessions.contains("remove_dir"),
        "handlers must not delete recording files directly"
    );
    assert!(
        !sessions.contains("remove_file"),
        "handlers must not delete recording files directly"
    );
}

#[test]
fn task_name_pin() {
    assert_eq!(TASK_NAME, "recording_reaper");
}

// ---------------------------------------------------------------------------
// run_bootstrap_retention on an empty backlog must exit promptly
// (`bootstrap_complete { age_reaped=0, quota_reaped=0 }`) -- the first
// tick finds no candidates and breaks out of the loop.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn bootstrap_exits_immediately_on_empty_backlog() {
    use std::time::Duration;
    use vauban_web::tasks::{run_bootstrap_retention, RecordingRetentionTaskConfig};

    let app = TestApp::spawn().await;
    if app.app_state.supervisor.is_none() {
        eprintln!(
            "skipped: no supervisor in test fixture; covered by source-level pin and prod smoke"
        );
        return;
    }
    let supervisor = std::sync::Arc::clone(app.app_state.supervisor.as_ref().unwrap());
    let handle = tokio::runtime::Handle::current();
    let started = std::time::Instant::now();
    let join = run_bootstrap_retention(
        &handle,
        app.db_pool.clone(),
        supervisor,
        RecordingRetentionTaskConfig {
            retention_days: 365,
            max_size_gib: 0,
            batch_size: 50,
            storage_base: "recordings".to_string(),
            cron_tz: chrono_tz::Tz::Europe__Brussels,
            cron_hour: 5,
        },
    );
    let r = tokio::time::timeout(Duration::from_secs(5), join).await;
    assert!(r.is_ok(), "bootstrap must exit in <5s on an empty backlog");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "bootstrap on empty backlog must be sub-5s"
    );
}
