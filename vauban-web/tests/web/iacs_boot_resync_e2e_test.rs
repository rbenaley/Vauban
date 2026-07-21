//! E2E: IACS boot resync via Snapshot IPC + pure apply plan.
//!
//! Covers:
//! 1. terminated DB row + matching proxy entry -> Rehydrate restores status
//! 2. live DB row + empty snapshot -> TerminateDb
//! 3. proxy UUID without DB row -> TerminateProxy IPC (`boot_orphan`)
//! 4. main.rs boot order pins

use crate::common::TestApp;
use crate::fixtures::{create_simple_user, unique_name};
use chrono::Utc;
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serial_test::serial;
use shared::messages::{
    IACS_SNAPSHOT_PHASE_TUNNEL_ACTIVE, IacsTunnelSnapshotEntry, Message,
};
use std::sync::Arc;
use uuid::Uuid;
use vauban_web::services::iacs_tunnel::{
    BootAction, apply_boot_reconcile_plan, reconcile_iacs_from_proxy_snapshot,
};

async fn seed_iacs_asset(conn: &mut AsyncPgConnection, admin_id: i32) -> i32 {
    use vauban_web::schema::assets;
    let label = unique_name("boot_asset");
    diesel::insert_into(assets::table)
        .values((
            assets::uuid.eq(Uuid::new_v4()),
            assets::name.eq(label.clone()),
            assets::hostname.eq(format!("{}.test.local", label)),
            assets::port.eq(4321),
            assets::asset_type.eq("iacs_modbus"),
            assets::status.eq("online"),
            assets::connection_username.eq(""),
            assets::connection_config.eq(serde_json::json!({})),
            assets::created_by_id.eq(admin_id),
        ))
        .returning(assets::id)
        .get_result(conn)
        .await
        .expect("seed asset")
}

async fn seed_ews(conn: &mut AsyncPgConnection, user_id: i32) -> Uuid {
    let request_uuid = Uuid::new_v4();
    let ews_uuid = Uuid::new_v4();
    let now = Utc::now();
    let label = unique_name("boot_ews");
    let fp = format!("{:0>64}", Uuid::new_v4().simple());

    diesel::sql_query(
        "INSERT INTO ews_onboarding_requests \
         (uuid, user_id, name, public_key, public_key_fingerprint, key_algo, \
          status, justification, decided_by_id, decided_at, created_at, updated_at) \
         VALUES ($1, $2, $3, 'ssh-ed25519 placeholder', $4, 'ed25519', \
                 'approved', 'seed-justification', $2, $5, $5, $5)",
    )
    .bind::<diesel::sql_types::Uuid, _>(request_uuid)
    .bind::<diesel::sql_types::Integer, _>(user_id)
    .bind::<diesel::sql_types::Text, _>(label.clone())
    .bind::<diesel::sql_types::Text, _>(&fp)
    .bind::<diesel::sql_types::Timestamptz, _>(now)
    .execute(conn)
    .await
    .expect("seed onboarding");

    diesel::sql_query(
        "INSERT INTO ews \
         (uuid, request_uuid, user_id, name, public_key, public_key_fingerprint, \
          key_algo, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, 'ssh-ed25519 placeholder', $5, 'ed25519', $6, $6)",
    )
    .bind::<diesel::sql_types::Uuid, _>(ews_uuid)
    .bind::<diesel::sql_types::Uuid, _>(request_uuid)
    .bind::<diesel::sql_types::Integer, _>(user_id)
    .bind::<diesel::sql_types::Text, _>(label)
    .bind::<diesel::sql_types::Text, _>(&fp)
    .bind::<diesel::sql_types::Timestamptz, _>(now)
    .execute(conn)
    .await
    .expect("seed ews");
    ews_uuid
}

async fn seed_session(
    conn: &mut AsyncPgConnection,
    user_id: i32,
    asset_id: i32,
    ews_uuid: Uuid,
    status: &str,
) -> Uuid {
    let session_uuid = Uuid::new_v4();
    let now = Utc::now();
    diesel::sql_query(
        "INSERT INTO proxy_sessions \
         (uuid, user_id, asset_id, credential_id, credential_username, session_type, status, \
          client_ip, industrial_protocol, ews_uuid, disconnected_at, created_at, updated_at) \
         VALUES ($1, $2, $3, '', '', 'iacs_tunnel', $4, '127.0.0.1/32', \
                 'modbus', $5, CASE WHEN $4 = 'terminated' THEN $6 ELSE NULL END, $6, $6)",
    )
    .bind::<diesel::sql_types::Uuid, _>(session_uuid)
    .bind::<diesel::sql_types::Integer, _>(user_id)
    .bind::<diesel::sql_types::Integer, _>(asset_id)
    .bind::<diesel::sql_types::Text, _>(status)
    .bind::<diesel::sql_types::Uuid, _>(ews_uuid)
    .bind::<diesel::sql_types::Timestamptz, _>(now)
    .execute(conn)
    .await
    .expect("seed session");
    session_uuid
}

async fn read_status(conn: &mut AsyncPgConnection, uuid: Uuid) -> String {
    use vauban_web::schema::proxy_sessions;
    proxy_sessions::table
        .filter(proxy_sessions::uuid.eq(uuid))
        .select(proxy_sessions::status)
        .first(conn)
        .await
        .expect("status")
}

fn snapshot_entry(id: Uuid, phase: u8) -> IacsTunnelSnapshotEntry {
    IacsTunnelSnapshotEntry {
        session_id: id.to_string(),
        phase,
        peer_ip: Some("203.0.113.50".into()),
        bytes_in: 10,
        bytes_out: 20,
        user_uuid: Uuid::new_v4().to_string(),
        asset_uuid: Uuid::new_v4().to_string(),
        ews_uuid: Uuid::new_v4().to_string(),
    }
}

/// Mock proxy-iacs: answers SnapshotRequest with `entries`, forwards
/// Terminate onto `term_tx`. Runs the web client's `process_incoming`
/// pump so oneshot responses are delivered.
fn spawn_mock_proxy(
    entries: Vec<IacsTunnelSnapshotEntry>,
) -> (
    Arc<vauban_web::ipc::proxy_iacs::ProxyIacsClient>,
    std::sync::mpsc::Receiver<Message>,
) {
    let (web_side, proxy_side) = shared::ipc::IpcChannel::pair().expect("ipc pair");
    let read_fd = web_side.read_fd();
    let write_fd = web_side.write_fd();
    std::mem::forget(web_side);
    let client = vauban_web::ipc::proxy_iacs::ProxyIacsClient::new(read_fd, write_fd)
        .expect("client");

    let (term_tx, term_rx) = std::sync::mpsc::channel();
    let client_for_pump = Arc::clone(&client);
    tokio::spawn(async move {
        let _ = client_for_pump.process_incoming().await;
    });

    // Blocking mock loop on a worker thread (recv polls non-blocking FDs).
    std::thread::spawn(move || {
        loop {
            match proxy_side.recv() {
                Ok(Message::IacsTunnelSnapshotRequest { request_id }) => {
                    if let Err(e) = proxy_side.send(&Message::IacsTunnelSnapshotResponse {
                        request_id,
                        entries: entries.clone(),
                    }) {
                        eprintln!("mock proxy: snapshot send failed: {e}");
                        break;
                    }
                }
                Ok(msg @ Message::IacsTunnelTerminate { .. }) => {
                    let _ = term_tx.send(msg);
                }
                Ok(_) => {}
                Err(e) => {
                    eprintln!("mock proxy: recv ended: {e}");
                    break;
                }
            }
        }
    });

    (client, term_rx)
}

#[tokio::test]
#[serial]
async fn boot_rehydrate_restores_terminated_row_from_proxy_entry() {
    let app = TestApp::spawn().await;
    let session_uuid = {
        let mut conn = app.get_conn().await;
        let user_id = create_simple_user(&mut conn, &unique_name("boot_reh")).await;
        let asset_id = seed_iacs_asset(&mut conn, user_id).await;
        let ews_uuid = seed_ews(&mut conn, user_id).await;
        seed_session(&mut conn, user_id, asset_id, ews_uuid, "terminated").await
    };

    let (client, _term_rx) = spawn_mock_proxy(vec![snapshot_entry(
        session_uuid,
        IACS_SNAPSHOT_PHASE_TUNNEL_ACTIVE,
    )]);
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let stats = reconcile_iacs_from_proxy_snapshot(&app.db_pool, client.as_ref())
        .await
        .expect("resync");
    assert!(
        stats.rehydrated >= 1,
        "expected at least our terminated row to be rehydrated, got {stats:?}"
    );

    let mut conn = app.get_conn().await;
    assert_eq!(read_status(&mut conn, session_uuid).await, "tunnel_active");

    use vauban_web::schema::proxy_sessions;
    let disconnected: Option<chrono::DateTime<Utc>> = proxy_sessions::table
        .filter(proxy_sessions::uuid.eq(session_uuid))
        .select(proxy_sessions::disconnected_at)
        .first(&mut conn)
        .await
        .expect("disconnected_at");
    assert!(disconnected.is_none(), "rehydrate must clear disconnected_at");
}

#[tokio::test]
#[serial]
async fn boot_empty_snapshot_terminates_live_db_rows() {
    let app = TestApp::spawn().await;
    let session_uuid = {
        let mut conn = app.get_conn().await;
        let user_id = create_simple_user(&mut conn, &unique_name("boot_empty")).await;
        let asset_id = seed_iacs_asset(&mut conn, user_id).await;
        let ews_uuid = seed_ews(&mut conn, user_id).await;
        seed_session(&mut conn, user_id, asset_id, ews_uuid, "tunnel_active").await
    };

    let (client, _term_rx) = spawn_mock_proxy(vec![]);
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let stats = reconcile_iacs_from_proxy_snapshot(&app.db_pool, client.as_ref())
        .await
        .expect("resync");
    assert!(
        stats.terminated_db >= 1,
        "empty snapshot must terminate live rows, got {stats:?}"
    );
    let mut conn = app.get_conn().await;
    assert_eq!(read_status(&mut conn, session_uuid).await, "terminated");
}

#[tokio::test]
#[serial]
async fn boot_unknown_proxy_uuid_dispatches_terminate_proxy() {
    let app = TestApp::spawn().await;
    let orphan = Uuid::new_v4();
    let (client, term_rx) = spawn_mock_proxy(vec![snapshot_entry(
        orphan,
        IACS_SNAPSHOT_PHASE_TUNNEL_ACTIVE,
    )]);
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let stats = reconcile_iacs_from_proxy_snapshot(&app.db_pool, client.as_ref())
        .await
        .expect("resync");
    assert!(
        stats.terminated_proxy >= 1,
        "unknown proxy UUID must TerminateProxy, got {stats:?}"
    );

    let msg = term_rx
        .recv_timeout(std::time::Duration::from_secs(3))
        .expect("TerminateProxy IPC");
    match msg {
        Message::IacsTunnelTerminate {
            session_id, reason, ..
        } => {
            assert_eq!(session_id, orphan.to_string());
            assert_eq!(reason, "boot_orphan");
        }
        other => panic!("expected IacsTunnelTerminate, got {other:?}"),
    }
}

#[tokio::test]
#[serial]
async fn apply_plan_rehydrate_and_terminate_db_without_snapshot() {
    // Direct apply path (no mock snapshot): pins the UPDATE shapes.
    let app = TestApp::spawn().await;
    let (revive, stale) = {
        let mut conn = app.get_conn().await;
        let user_id = create_simple_user(&mut conn, &unique_name("boot_apply")).await;
        let asset_id = seed_iacs_asset(&mut conn, user_id).await;
        let ews_uuid = seed_ews(&mut conn, user_id).await;
        let revive = seed_session(&mut conn, user_id, asset_id, ews_uuid, "terminated").await;
        let stale = seed_session(&mut conn, user_id, asset_id, ews_uuid, "ews_connected").await;
        (revive, stale)
    };

    let (client, _) = spawn_mock_proxy(vec![]);
    let plan = vec![
        BootAction::Rehydrate {
            session_id: revive,
            phase: IACS_SNAPSHOT_PHASE_TUNNEL_ACTIVE,
            peer_ip: Some("198.51.100.7".into()),
            bytes_in: 1,
            bytes_out: 2,
        },
        BootAction::TerminateDb { session_id: stale },
    ];
    let stats = apply_boot_reconcile_plan(&app.db_pool, Some(client.as_ref()), &plan)
        .await
        .expect("apply");
    assert_eq!(stats.rehydrated, 1, "rehydrate must update the terminated row");
    assert_eq!(stats.terminated_db, 1);

    let mut conn = app.get_conn().await;
    assert_eq!(read_status(&mut conn, revive).await, "tunnel_active");
    assert_eq!(read_status(&mut conn, stale).await, "terminated");
}

#[test]
fn main_boot_calls_proxy_snapshot_resync_after_ipc_init() {
    let src = include_str!("../../src/main.rs");
    let init_pos = src
        .find("init_iacs_proxy_client")
        .expect("init_iacs_proxy_client present");
    let pump_pos = src
        .find("process_incoming_with_state")
        .expect("IACS pump started");
    let resync_pos = src
        .find("reconcile_iacs_from_proxy_snapshot")
        .expect("main MUST call reconcile_iacs_from_proxy_snapshot");
    assert!(
        init_pos < pump_pos && pump_pos < resync_pos,
        "boot order must be: init_iacs_proxy_client -> IPC pump -> \
         reconcile_iacs_from_proxy_snapshot (got init={init_pos} \
         pump={pump_pos} resync={resync_pos})"
    );
    // Early mass-terminate before IPC init is forbidden.
    let early = &src[..init_pos];
    assert!(
        !early.contains("reconcile_orphaned_iacs_tunnels_on_boot")
            && !early.contains("reconcile_iacs_from_proxy_snapshot"),
        "main MUST NOT reconcile IACS rows before init_iacs_proxy_client"
    );
}
