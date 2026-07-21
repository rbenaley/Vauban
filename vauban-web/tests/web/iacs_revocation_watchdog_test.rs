//! L4 -- IACS revocation watchdog tests (IPC-only).
//!
//! These tests pin the cross-process revocation contract:
//!
//!   * an admin disables an EWS via `vauban-access` -- the
//!     watchdog must flip the live row to `terminated` and
//!     dispatch `IacsTunnelTerminate` when a proxy client is wired;
//!   * same with `offboarded_at`;
//!   * same with `users.is_active=false`;
//!   * the watchdog does NOT touch tunnels owned by other users;
//!   * `waiting_client` rows older than the TTL flip to `expired`;
//!   * the audit log gains a `tunnel_closed` row per revocation.
//!
//! The tests drive a single `run_once` tick deterministically
//! instead of waiting for the tokio interval, so they are fast
//! and independent of CI scheduling.

use crate::common::TestApp;
use crate::fixtures::{create_simple_user, unique_name};
use chrono::Utc;
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serial_test::serial;
use uuid::Uuid;
use vauban_web::config::IacsTunnelConfig;
use vauban_web::services::iacs_tunnel::{
    BootAction, apply_boot_reconcile_plan, watchdog_run_once,
};

// ===================================================================
// Test fixtures
// ===================================================================

async fn seed_iacs_asset(conn: &mut AsyncPgConnection, admin_id: i32) -> i32 {
    use vauban_web::schema::assets;
    let label = unique_name("revoke_asset");
    let id: i32 = diesel::insert_into(assets::table)
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
        .expect("seed asset");
    id
}

async fn seed_ews(conn: &mut AsyncPgConnection, user_id: i32) -> Uuid {
    let request_uuid = Uuid::new_v4();
    let ews_uuid = Uuid::new_v4();
    let now = Utc::now();
    let label = unique_name("revoke_ews");
    let fp = format!("{:0>64}", Uuid::new_v4().simple().to_string());

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
    .expect("seed onboarding request");

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

/// Insert a `proxy_sessions` row in `tunnel_active`. Returns the
/// session UUID.
async fn seed_active_session(
    conn: &mut AsyncPgConnection,
    user_id: i32,
    asset_id: i32,
    ews_uuid: Uuid,
) -> Uuid {
    let uuid = Uuid::new_v4();
    diesel::sql_query(
        "INSERT INTO proxy_sessions \
         (uuid, user_id, asset_id, credential_id, credential_username, \
          session_type, status, client_ip, ews_uuid, industrial_protocol, \
          tunnel_target_addr) \
         VALUES ($1, $2, $3, '', '', 'iacs_tunnel', 'tunnel_active', \
                 '127.0.0.1'::inet, $4, 'iacs_modbus', '127.0.0.1:4321')",
    )
    .bind::<diesel::sql_types::Uuid, _>(uuid)
    .bind::<diesel::sql_types::Integer, _>(user_id)
    .bind::<diesel::sql_types::Integer, _>(asset_id)
    .bind::<diesel::sql_types::Uuid, _>(ews_uuid)
    .execute(conn)
    .await
    .expect("seed active session");
    uuid
}

async fn read_session_status(conn: &mut AsyncPgConnection, uuid: Uuid) -> String {
    use vauban_web::schema::proxy_sessions;
    proxy_sessions::table
        .filter(proxy_sessions::uuid.eq(uuid))
        .select(proxy_sessions::status)
        .first(conn)
        .await
        .expect("status")
}

fn cfg_with_ttl(ttl: u32) -> IacsTunnelConfig {
    IacsTunnelConfig {
        bind_addr: "127.0.0.1:0".to_string(),
        advertise_hostname: "127.0.0.1".to_string(),
        host_key_path: "/tmp/never_used".to_string(),
        max_concurrent_per_user: 0,
        max_concurrent_per_ews: 0,
        max_concurrent_channels_per_session: 16,
        waiting_client_ttl_seconds: ttl,
        revocation_poll_interval_seconds: 1,
    }
}

// ===================================================================
// Tests
// ===================================================================

#[tokio::test]
#[serial]
async fn watchdog_closes_tunnels_when_ews_disabled() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let user_id = create_simple_user(&mut conn, &unique_name("watchdog_dis")).await;
    let asset_id = seed_iacs_asset(&mut conn, user_id).await;
    let ews_uuid = seed_ews(&mut conn, user_id).await;
    let session_uuid = seed_active_session(&mut conn, user_id, asset_id, ews_uuid).await;

    diesel::sql_query("UPDATE ews SET disabled_at = NOW() WHERE uuid = $1")
        .bind::<diesel::sql_types::Uuid, _>(ews_uuid)
        .execute(&mut conn)
        .await
        .expect("disable ews");

    let cfg = cfg_with_ttl(0);
    let (closed, _) = watchdog_run_once(&app.db_pool, &cfg, None).await;
    assert_eq!(closed, 1, "watchdog must close exactly the disabled tunnel");
    assert_eq!(
        read_session_status(&mut conn, session_uuid).await,
        "terminated"
    );
}

#[tokio::test]
#[serial]
async fn watchdog_closes_tunnels_when_ews_offboarded() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let user_id = create_simple_user(&mut conn, &unique_name("watchdog_off")).await;
    let asset_id = seed_iacs_asset(&mut conn, user_id).await;
    let ews_uuid = seed_ews(&mut conn, user_id).await;
    let session_uuid = seed_active_session(&mut conn, user_id, asset_id, ews_uuid).await;

    diesel::sql_query("UPDATE ews SET offboarded_at = NOW() WHERE uuid = $1")
        .bind::<diesel::sql_types::Uuid, _>(ews_uuid)
        .execute(&mut conn)
        .await
        .expect("offboard ews");

    let (closed, _) = watchdog_run_once(&app.db_pool, &cfg_with_ttl(0), None).await;
    assert_eq!(closed, 1);
    assert_eq!(
        read_session_status(&mut conn, session_uuid).await,
        "terminated"
    );
}

#[tokio::test]
#[serial]
async fn watchdog_closes_tunnels_when_user_deactivated() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let user_id = create_simple_user(&mut conn, &unique_name("watchdog_user")).await;
    let asset_id = seed_iacs_asset(&mut conn, user_id).await;
    let ews_uuid = seed_ews(&mut conn, user_id).await;
    let session_uuid = seed_active_session(&mut conn, user_id, asset_id, ews_uuid).await;

    use vauban_web::schema::users;
    diesel::update(users::table.filter(users::id.eq(user_id)))
        .set(users::is_active.eq(false))
        .execute(&mut conn)
        .await
        .expect("deactivate user");

    let (closed, _) = watchdog_run_once(&app.db_pool, &cfg_with_ttl(0), None).await;
    assert_eq!(closed, 1);
    assert_eq!(
        read_session_status(&mut conn, session_uuid).await,
        "terminated"
    );
}

#[tokio::test]
#[serial]
async fn watchdog_does_not_touch_other_users_tunnels() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let user_a = create_simple_user(&mut conn, &unique_name("watchdog_a")).await;
    let user_b = create_simple_user(&mut conn, &unique_name("watchdog_b")).await;
    let asset_a = seed_iacs_asset(&mut conn, user_a).await;
    let asset_b = seed_iacs_asset(&mut conn, user_b).await;
    let ews_a = seed_ews(&mut conn, user_a).await;
    let ews_b = seed_ews(&mut conn, user_b).await;
    let session_a = seed_active_session(&mut conn, user_a, asset_a, ews_a).await;
    let session_b = seed_active_session(&mut conn, user_b, asset_b, ews_b).await;

    diesel::sql_query("UPDATE ews SET disabled_at = NOW() WHERE uuid = $1")
        .bind::<diesel::sql_types::Uuid, _>(ews_a)
        .execute(&mut conn)
        .await
        .expect("disable ews_a");

    let (closed, _) = watchdog_run_once(&app.db_pool, &cfg_with_ttl(0), None).await;
    assert_eq!(closed, 1, "exactly one tunnel must be revoked");
    assert_eq!(
        read_session_status(&mut conn, session_a).await,
        "terminated",
        "A must be revoked"
    );
    assert_eq!(
        read_session_status(&mut conn, session_b).await,
        "tunnel_active",
        "B must survive"
    );
}

#[tokio::test]
#[serial]
async fn watchdog_expires_waiting_client_past_ttl() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let user_id = create_simple_user(&mut conn, &unique_name("watchdog_ttl")).await;
    let asset_id = seed_iacs_asset(&mut conn, user_id).await;
    let ews_uuid = seed_ews(&mut conn, user_id).await;

    let session_uuid = Uuid::new_v4();
    let stale = Utc::now() - chrono::Duration::seconds(120);
    diesel::sql_query(
        "INSERT INTO proxy_sessions \
         (uuid, user_id, asset_id, credential_id, credential_username, \
          session_type, status, client_ip, ews_uuid, industrial_protocol, \
          tunnel_target_addr, created_at) \
         VALUES ($1, $2, $3, '', '', 'iacs_tunnel', 'waiting_client', \
                 '127.0.0.1'::inet, $4, 'iacs_modbus', '127.0.0.1:4321', $5)",
    )
    .bind::<diesel::sql_types::Uuid, _>(session_uuid)
    .bind::<diesel::sql_types::Integer, _>(user_id)
    .bind::<diesel::sql_types::Integer, _>(asset_id)
    .bind::<diesel::sql_types::Uuid, _>(ews_uuid)
    .bind::<diesel::sql_types::Timestamptz, _>(stale)
    .execute(&mut conn)
    .await
    .expect("seed stale waiting_client");

    let (_, transitions) = watchdog_run_once(&app.db_pool, &cfg_with_ttl(60), None).await;
    assert!(transitions >= 1, "stale waiting_client must transition");
    assert_eq!(
        read_session_status(&mut conn, session_uuid).await,
        "expired"
    );
}

#[tokio::test]
#[serial]
async fn watchdog_does_not_expire_recent_waiting_client() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let user_id = create_simple_user(&mut conn, &unique_name("watchdog_recent")).await;
    let asset_id = seed_iacs_asset(&mut conn, user_id).await;
    let ews_uuid = seed_ews(&mut conn, user_id).await;
    let session_uuid = Uuid::new_v4();
    diesel::sql_query(
        "INSERT INTO proxy_sessions \
         (uuid, user_id, asset_id, credential_id, credential_username, \
          session_type, status, client_ip, ews_uuid, industrial_protocol, \
          tunnel_target_addr) \
         VALUES ($1, $2, $3, '', '', 'iacs_tunnel', 'waiting_client', \
                 '127.0.0.1'::inet, $4, 'iacs_modbus', '127.0.0.1:4321')",
    )
    .bind::<diesel::sql_types::Uuid, _>(session_uuid)
    .bind::<diesel::sql_types::Integer, _>(user_id)
    .bind::<diesel::sql_types::Integer, _>(asset_id)
    .bind::<diesel::sql_types::Uuid, _>(ews_uuid)
    .execute(&mut conn)
    .await
    .expect("seed fresh waiting_client");

    let _ = watchdog_run_once(&app.db_pool, &cfg_with_ttl(60), None).await;
    assert_eq!(
        read_session_status(&mut conn, session_uuid).await,
        "waiting_client",
        "fresh waiting_client must NOT be expired"
    );
}

#[tokio::test]
#[serial]
async fn watchdog_expires_stale_ews_connected_past_ttl() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let user_id = create_simple_user(&mut conn, &unique_name("watchdog_ews_ttl")).await;
    let asset_id = seed_iacs_asset(&mut conn, user_id).await;
    let ews_uuid = seed_ews(&mut conn, user_id).await;

    let session_uuid = Uuid::new_v4();
    let stale = Utc::now() - chrono::Duration::seconds(120);
    diesel::sql_query(
        "INSERT INTO proxy_sessions \
         (uuid, user_id, asset_id, credential_id, credential_username, \
          session_type, status, client_ip, ews_uuid, industrial_protocol, \
          tunnel_target_addr, created_at, connected_at) \
         VALUES ($1, $2, $3, '', '', 'iacs_tunnel', 'ews_connected', \
                 '127.0.0.1'::inet, $4, 'iacs_modbus', '127.0.0.1:4321', NOW(), $5)",
    )
    .bind::<diesel::sql_types::Uuid, _>(session_uuid)
    .bind::<diesel::sql_types::Integer, _>(user_id)
    .bind::<diesel::sql_types::Integer, _>(asset_id)
    .bind::<diesel::sql_types::Uuid, _>(ews_uuid)
    .bind::<diesel::sql_types::Timestamptz, _>(stale)
    .execute(&mut conn)
    .await
    .expect("seed stale ews_connected");

    let (_, transitions) = watchdog_run_once(&app.db_pool, &cfg_with_ttl(60), None).await;
    assert!(transitions >= 1, "stale ews_connected must transition");
    assert_eq!(
        read_session_status(&mut conn, session_uuid).await,
        "expired"
    );
}

#[tokio::test]
#[serial]
async fn watchdog_does_not_expire_ews_connected_with_fresh_connected_at() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let user_id = create_simple_user(&mut conn, &unique_name("watchdog_ews_fresh")).await;
    let asset_id = seed_iacs_asset(&mut conn, user_id).await;
    let ews_uuid = seed_ews(&mut conn, user_id).await;

    let session_uuid = Uuid::new_v4();
    let stale_created = Utc::now() - chrono::Duration::seconds(3600);
    diesel::sql_query(
        "INSERT INTO proxy_sessions \
         (uuid, user_id, asset_id, credential_id, credential_username, \
          session_type, status, client_ip, ews_uuid, industrial_protocol, \
          tunnel_target_addr, created_at, connected_at) \
         VALUES ($1, $2, $3, '', '', 'iacs_tunnel', 'ews_connected', \
                 '127.0.0.1'::inet, $4, 'iacs_modbus', '127.0.0.1:4321', $5, NOW())",
    )
    .bind::<diesel::sql_types::Uuid, _>(session_uuid)
    .bind::<diesel::sql_types::Integer, _>(user_id)
    .bind::<diesel::sql_types::Integer, _>(asset_id)
    .bind::<diesel::sql_types::Uuid, _>(ews_uuid)
    .bind::<diesel::sql_types::Timestamptz, _>(stale_created)
    .execute(&mut conn)
    .await
    .expect("seed fresh ews_connected");

    let _ = watchdog_run_once(&app.db_pool, &cfg_with_ttl(60), None).await;
    assert_eq!(
        read_session_status(&mut conn, session_uuid).await,
        "ews_connected",
        "fresh ews_connected (anchored on connected_at) must NOT expire"
    );
}

/// Proxy topology: when the TTL reaps an `ews_connected` row, the
/// watchdog must ALSO dispatch `IacsTunnelTerminate { reason =
/// "expired" }` over IPC -- the silent SSH login lives in proxy-iacs
/// and has no relay task to break, so only the IPC can cut it.
#[tokio::test]
#[serial]
async fn watchdog_dispatches_terminate_ipc_for_expired_ews_connected() {
    use std::sync::Arc;

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let user_id = create_simple_user(&mut conn, &unique_name("watchdog_ews_ipc")).await;
    let asset_id = seed_iacs_asset(&mut conn, user_id).await;
    let ews_uuid = seed_ews(&mut conn, user_id).await;

    let session_uuid = Uuid::new_v4();
    let stale = Utc::now() - chrono::Duration::seconds(120);
    diesel::sql_query(
        "INSERT INTO proxy_sessions \
         (uuid, user_id, asset_id, credential_id, credential_username, \
          session_type, status, client_ip, ews_uuid, industrial_protocol, \
          tunnel_target_addr, created_at, connected_at) \
         VALUES ($1, $2, $3, '', '', 'iacs_tunnel', 'ews_connected', \
                 '127.0.0.1'::inet, $4, 'iacs_modbus', '127.0.0.1:4321', $5, $5)",
    )
    .bind::<diesel::sql_types::Uuid, _>(session_uuid)
    .bind::<diesel::sql_types::Integer, _>(user_id)
    .bind::<diesel::sql_types::Integer, _>(asset_id)
    .bind::<diesel::sql_types::Uuid, _>(ews_uuid)
    .bind::<diesel::sql_types::Timestamptz, _>(stale)
    .execute(&mut conn)
    .await
    .expect("seed stale ews_connected");

    let (web_side, proxy_side) = shared::ipc::IpcChannel::pair().expect("ipc pair");
    let read_fd = web_side.read_fd();
    let write_fd = web_side.write_fd();
    std::mem::forget(web_side);
    let client = Arc::new(
        vauban_web::ipc::proxy_iacs::ProxyIacsClient::new(read_fd, write_fd)
            .expect("proxy iacs client"),
    );

    let (_, transitions) = vauban_web::services::iacs_tunnel::run_once_with_proxy(
        &app.db_pool,
        &cfg_with_ttl(60),
        Some(&client),
    )
    .await;
    assert!(transitions >= 1, "stale ews_connected must be reaped");
    assert_eq!(
        read_session_status(&mut conn, session_uuid).await,
        "expired"
    );

    let msg = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        tokio::task::spawn_blocking(move || proxy_side.recv()),
    )
    .await
    .expect("timed out waiting for the terminate IPC")
    .expect("join")
    .expect("recv");
    match msg {
        shared::messages::Message::IacsTunnelTerminate {
            session_id, reason, ..
        } => {
            assert_eq!(session_id, session_uuid.to_string());
            assert_eq!(reason, "expired");
        }
        other => panic!("expected IacsTunnelTerminate, got {:?}", other),
    }
}

#[tokio::test]
#[serial]
async fn watchdog_appends_tunnel_closed_audit_row() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let user_id = create_simple_user(&mut conn, &unique_name("watchdog_audit")).await;
    let asset_id = seed_iacs_asset(&mut conn, user_id).await;
    let ews_uuid = seed_ews(&mut conn, user_id).await;
    let session_uuid = seed_active_session(&mut conn, user_id, asset_id, ews_uuid).await;

    diesel::sql_query("UPDATE ews SET disabled_at = NOW() WHERE uuid = $1")
        .bind::<diesel::sql_types::Uuid, _>(ews_uuid)
        .execute(&mut conn)
        .await
        .expect("disable");

    let _ = watchdog_run_once(&app.db_pool, &cfg_with_ttl(0), None).await;
    let _ = session_uuid;

    #[derive(diesel::QueryableByName, Debug)]
    struct AuditRow {
        #[diesel(sql_type = diesel::sql_types::Text)]
        #[allow(dead_code)]
        event: String,
    }
    let rows: Vec<AuditRow> = diesel::sql_query(
        "SELECT event FROM ews_audit_log \
         WHERE ews_uuid = $1 AND event = 'tunnel_closed'",
    )
    .bind::<diesel::sql_types::Uuid, _>(ews_uuid)
    .load(&mut conn)
    .await
    .expect("query audit");
    assert!(
        !rows.is_empty(),
        "watchdog must append a tunnel_closed audit row"
    );
}

/// Empty-snapshot fail-closed path scoped to seeded UUIDs only
/// (never a global UPDATE -- that races other parallel IACS suites).
/// Full Snapshot resync E2E lives in `iacs_boot_resync_e2e_test.rs`.
#[tokio::test]
#[serial]
async fn boot_reconcile_terminates_stale_tunnel_active_and_waiting_client() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let user_id = create_simple_user(&mut conn, &unique_name("boot_reconcile")).await;
    let asset_id = seed_iacs_asset(&mut conn, user_id).await;
    let ews_uuid = seed_ews(&mut conn, user_id).await;
    let active_uuid = seed_active_session(&mut conn, user_id, asset_id, ews_uuid).await;

    let waiting_uuid = Uuid::new_v4();
    diesel::sql_query(
        "INSERT INTO proxy_sessions \
         (uuid, user_id, asset_id, credential_id, credential_username, session_type, status, \
          client_ip, industrial_protocol, ews_uuid) \
         VALUES ($1, $2, $3, '', '', 'iacs_tunnel', 'waiting_client', '127.0.0.1/32', \
                 'modbus', $4)",
    )
    .bind::<diesel::sql_types::Uuid, _>(waiting_uuid)
    .bind::<diesel::sql_types::Integer, _>(user_id)
    .bind::<diesel::sql_types::Integer, _>(asset_id)
    .bind::<diesel::sql_types::Uuid, _>(ews_uuid)
    .execute(&mut conn)
    .await
    .expect("seed waiting_client");
    drop(conn);

    let plan = vec![
        BootAction::TerminateDb {
            session_id: active_uuid,
        },
        BootAction::TerminateDb {
            session_id: waiting_uuid,
        },
    ];
    let stats = apply_boot_reconcile_plan(&app.db_pool, None, &plan)
        .await
        .expect("apply terminate plan");
    assert_eq!(stats.terminated_db, 2);

    use vauban_web::schema::proxy_sessions;
    let mut conn = app.get_conn().await;
    for uuid in [active_uuid, waiting_uuid] {
        let status: String = proxy_sessions::table
            .filter(proxy_sessions::uuid.eq(uuid))
            .select(proxy_sessions::status)
            .first(&mut conn)
            .await
            .expect("load status");
        assert_eq!(
            status, "terminated",
            "boot reconcile must flip seeded row {uuid} to terminated"
        );
    }
}
