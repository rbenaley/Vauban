//! L4 -- IACS revocation watchdog tests.
//!
//! These tests pin the cross-process revocation contract:
//!
//!   * an admin disables an EWS via `vauban-access` -- the
//!     watchdog must close every active tunnel anchored on that
//!     EWS within `revocation_poll_interval_seconds` + a small
//!     fudge factor;
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
use uuid::Uuid;
use vauban_web::config::IacsTunnelConfig;
use vauban_web::services::iacs_tunnel::{
    TunnelHandle, TunnelRegistry, reconcile_orphaned_iacs_tunnels_on_boot, watchdog_run_once,
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
            assets::status.eq("active"),
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
    let fp = format!("{:0>64}", &Uuid::new_v4().simple().to_string());

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
/// session UUID. The caller is expected to also `register_handle`
/// so the watchdog can find a live tunnel to revoke.
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
        target_addr: "127.0.0.1:65535".to_string(),
        host_key_path: "/tmp/never_used".to_string(),
        max_concurrent_per_user: 0,
        max_concurrent_per_ews: 0,
        max_concurrent_channels_per_session: 16,
        waiting_client_ttl_seconds: ttl,
        revocation_poll_interval_seconds: 1,
    }
}

fn user_uuid_for(user_id: i32) -> Uuid {
    // Test users do not need their real UUID for the registry
    // (the watchdog never reads it back).
    let _ = user_id;
    Uuid::new_v4()
}

// ===================================================================
// Tests
// ===================================================================

#[tokio::test]
async fn watchdog_closes_tunnels_when_ews_disabled() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let user_id = create_simple_user(&mut conn, &unique_name("watchdog_dis")).await;
    let asset_id = seed_iacs_asset(&mut conn, user_id).await;
    let ews_uuid = seed_ews(&mut conn, user_id).await;
    let session_uuid = seed_active_session(&mut conn, user_id, asset_id, ews_uuid).await;

    let registry = TunnelRegistry::new();
    registry.insert(TunnelHandle::new(
        session_uuid,
        ews_uuid,
        user_uuid_for(user_id),
    ));

    // Disable the EWS (mimics the admin offboarding flow over IPC).
    diesel::sql_query("UPDATE ews SET disabled_at = NOW() WHERE uuid = $1")
        .bind::<diesel::sql_types::Uuid, _>(ews_uuid)
        .execute(&mut conn)
        .await
        .expect("disable ews");

    let cfg = cfg_with_ttl(0);
    let (closed, _) = watchdog_run_once(&registry, &app.db_pool, &cfg, true).await;
    assert_eq!(closed, 1, "watchdog must close exactly the disabled tunnel");
    assert!(registry.get(&session_uuid).is_none(), "registry must drop");
    assert_eq!(
        read_session_status(&mut conn, session_uuid).await,
        "terminated"
    );
}

#[tokio::test]
async fn watchdog_closes_tunnels_when_ews_offboarded() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let user_id = create_simple_user(&mut conn, &unique_name("watchdog_off")).await;
    let asset_id = seed_iacs_asset(&mut conn, user_id).await;
    let ews_uuid = seed_ews(&mut conn, user_id).await;
    let session_uuid = seed_active_session(&mut conn, user_id, asset_id, ews_uuid).await;

    let registry = TunnelRegistry::new();
    registry.insert(TunnelHandle::new(
        session_uuid,
        ews_uuid,
        user_uuid_for(user_id),
    ));

    diesel::sql_query("UPDATE ews SET offboarded_at = NOW() WHERE uuid = $1")
        .bind::<diesel::sql_types::Uuid, _>(ews_uuid)
        .execute(&mut conn)
        .await
        .expect("offboard ews");

    let (closed, _) = watchdog_run_once(&registry, &app.db_pool, &cfg_with_ttl(0), true).await;
    assert_eq!(closed, 1);
    assert!(registry.get(&session_uuid).is_none());
}

#[tokio::test]
async fn watchdog_closes_tunnels_when_user_deactivated() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let user_id = create_simple_user(&mut conn, &unique_name("watchdog_user")).await;
    let asset_id = seed_iacs_asset(&mut conn, user_id).await;
    let ews_uuid = seed_ews(&mut conn, user_id).await;
    let session_uuid = seed_active_session(&mut conn, user_id, asset_id, ews_uuid).await;

    let registry = TunnelRegistry::new();
    registry.insert(TunnelHandle::new(
        session_uuid,
        ews_uuid,
        user_uuid_for(user_id),
    ));

    use vauban_web::schema::users;
    diesel::update(users::table.filter(users::id.eq(user_id)))
        .set(users::is_active.eq(false))
        .execute(&mut conn)
        .await
        .expect("deactivate user");

    let (closed, _) = watchdog_run_once(&registry, &app.db_pool, &cfg_with_ttl(0), true).await;
    assert_eq!(closed, 1);
    assert!(registry.get(&session_uuid).is_none());
}

/// JIT revocation cascade contract: when the web layer flips a live
/// IACS row to `terminated` (e.g. `cascade_terminate_grant_sessions`
/// after a grant revoke, or the admin terminate endpoint), the
/// watchdog must cut the live tunnel on its next tick even though the
/// EWS and the user are both still perfectly valid.
#[tokio::test]
async fn watchdog_closes_tunnel_when_session_row_terminated() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let user_id = create_simple_user(&mut conn, &unique_name("watchdog_term")).await;
    let asset_id = seed_iacs_asset(&mut conn, user_id).await;
    let ews_uuid = seed_ews(&mut conn, user_id).await;
    let session_uuid = seed_active_session(&mut conn, user_id, asset_id, ews_uuid).await;

    let registry = TunnelRegistry::new();
    registry.insert(TunnelHandle::new(
        session_uuid,
        ews_uuid,
        user_uuid_for(user_id),
    ));

    // The revoke cascade flipped the row; EWS/user stay valid.
    use vauban_web::schema::proxy_sessions;
    diesel::update(proxy_sessions::table.filter(proxy_sessions::uuid.eq(session_uuid)))
        .set((
            proxy_sessions::status.eq("terminated"),
            proxy_sessions::disconnected_at.eq(Some(Utc::now())),
        ))
        .execute(&mut conn)
        .await
        .expect("terminate session row");

    let (closed, _) = watchdog_run_once(&registry, &app.db_pool, &cfg_with_ttl(0), true).await;
    assert_eq!(
        closed, 1,
        "watchdog must close the live tunnel of a terminated row"
    );
    assert!(
        registry.get(&session_uuid).is_none(),
        "registry must drop the terminated tunnel"
    );
    assert_eq!(
        read_session_status(&mut conn, session_uuid).await,
        "terminated",
        "row must stay terminated"
    );
}

#[tokio::test]
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

    let registry = TunnelRegistry::new();
    registry.insert(TunnelHandle::new(session_a, ews_a, user_uuid_for(user_a)));
    registry.insert(TunnelHandle::new(session_b, ews_b, user_uuid_for(user_b)));

    // Disable user A's EWS. User B must remain untouched.
    diesel::sql_query("UPDATE ews SET disabled_at = NOW() WHERE uuid = $1")
        .bind::<diesel::sql_types::Uuid, _>(ews_a)
        .execute(&mut conn)
        .await
        .expect("disable ews_a");

    let (closed, _) = watchdog_run_once(&registry, &app.db_pool, &cfg_with_ttl(0), true).await;
    assert_eq!(closed, 1, "exactly one tunnel must be revoked");
    assert!(registry.get(&session_a).is_none(), "A must be revoked");
    assert!(registry.get(&session_b).is_some(), "B must survive");
}

#[tokio::test]
async fn watchdog_expires_waiting_client_past_ttl() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let user_id = create_simple_user(&mut conn, &unique_name("watchdog_ttl")).await;
    let asset_id = seed_iacs_asset(&mut conn, user_id).await;
    let ews_uuid = seed_ews(&mut conn, user_id).await;

    // Insert directly so we control `created_at`.
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

    let registry = TunnelRegistry::new();
    let (_, transitions) =
        watchdog_run_once(&registry, &app.db_pool, &cfg_with_ttl(60), true).await;
    assert!(transitions >= 1, "stale waiting_client must transition");
    assert_eq!(
        read_session_status(&mut conn, session_uuid).await,
        "expired"
    );
}

#[tokio::test]
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

    let registry = TunnelRegistry::new();
    let _ = watchdog_run_once(&registry, &app.db_pool, &cfg_with_ttl(60), true).await;
    assert_eq!(
        read_session_status(&mut conn, session_uuid).await,
        "waiting_client",
        "fresh waiting_client must NOT be expired"
    );
}

#[tokio::test]
async fn watchdog_appends_tunnel_closed_audit_row() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let user_id = create_simple_user(&mut conn, &unique_name("watchdog_audit")).await;
    let asset_id = seed_iacs_asset(&mut conn, user_id).await;
    let ews_uuid = seed_ews(&mut conn, user_id).await;
    let session_uuid = seed_active_session(&mut conn, user_id, asset_id, ews_uuid).await;
    let registry = TunnelRegistry::new();
    registry.insert(TunnelHandle::new(
        session_uuid,
        ews_uuid,
        user_uuid_for(user_id),
    ));

    diesel::sql_query("UPDATE ews SET disabled_at = NOW() WHERE uuid = $1")
        .bind::<diesel::sql_types::Uuid, _>(ews_uuid)
        .execute(&mut conn)
        .await
        .expect("disable");

    let _ = watchdog_run_once(&registry, &app.db_pool, &cfg_with_ttl(0), true).await;

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

#[tokio::test]
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

    let n = reconcile_orphaned_iacs_tunnels_on_boot(&app.db_pool)
        .await
        .expect("reconcile");
    assert!(
        n >= 2,
        "boot reconcile must terminate at least the two seeded rows (got {n})"
    );

    use vauban_web::schema::proxy_sessions;
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

#[tokio::test]
async fn watchdog_reconciles_tunnel_active_rows_missing_from_registry() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let user_id = create_simple_user(&mut conn, &unique_name("registry_drift")).await;
    let asset_id = seed_iacs_asset(&mut conn, user_id).await;
    let ews_uuid = seed_ews(&mut conn, user_id).await;
    let orphan_uuid = seed_active_session(&mut conn, user_id, asset_id, ews_uuid).await;

    let registry = TunnelRegistry::new();
    let (_, transitions) = watchdog_run_once(&registry, &app.db_pool, &cfg_with_ttl(0), true).await;
    assert!(
        transitions >= 1,
        "registry drift must terminate tunnel_active rows absent from the registry"
    );

    use vauban_web::schema::proxy_sessions;
    let status: String = proxy_sessions::table
        .filter(proxy_sessions::uuid.eq(orphan_uuid))
        .select(proxy_sessions::status)
        .first(&mut conn)
        .await
        .expect("load status");
    assert_eq!(status, "terminated");
}

#[test]
fn main_boot_calls_iacs_tunnel_orphan_reconciliation() {
    let src = include_str!("../../src/main.rs");
    assert!(
        src.contains("reconcile_orphaned_iacs_tunnels_on_boot"),
        "main.rs MUST reconcile stale IACS proxy_sessions rows on boot"
    );
}
