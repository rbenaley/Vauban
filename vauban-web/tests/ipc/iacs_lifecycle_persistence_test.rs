//! IPC integration tests: IACS lifecycle persistence.
//!
//! These tests pin the behaviour of [`vauban_web::ipc::proxy_iacs`]'s
//! `persist_ews_connected` / `persist_tunnel_active` /
//! `persist_tunnel_closed` helpers without spawning a full
//! `vauban-proxy-iacs` subprocess. The helpers are the seam that
//! bridges:
//!
//!  - the `IacsTunnelStatusUpdate` / `IacsTunnelClosed` IPC messages
//!    pushed by `vauban-proxy-iacs`,
//!  - the admin `/sessions/active` page (whose SQL filter is
//!    `status IN ('active', 'ews_connected', 'tunnel_active') AND
//!    connected_at IS NOT NULL`).
//!
//! Without this seam the IACS lifecycle would never propagate to
//! the DB and the admin page would always show `0 IACS` (the bug
//! that motivated this surface).

use crate::common::{TestApp, unwrap_ok};
use crate::fixtures::{
    create_iacs_test_session_with_uuid, create_simple_admin_user, create_simple_iacs_asset,
    create_simple_user, unique_name,
};
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::RunQueryDsl;

// ===================================================================
// 0. ews_connected path (SSH auth, pre-channel)
// ===================================================================

/// Receiving `IacsTunnelStatusUpdate { status = "ews_connected",
/// peer_ip = Some(<EWS IP>) }` MUST flip the row from
/// `waiting_client` to `ews_connected`, anchor `connected_at` (the
/// watchdog TTL restarts on it) and overwrite `client_ip` with the
/// EWS source.
#[tokio::test]
async fn persist_ews_connected_flips_waiting_client_row() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_id = create_simple_admin_user(&mut conn, &unique_name("ews_conn_admin")).await;
    let user_id = create_simple_user(&mut conn, &unique_name("ews_conn_user")).await;
    let asset_id =
        create_simple_iacs_asset(&mut conn, &unique_name("ews-conn-iacs"), admin_id).await;
    let (_, session_uuid) =
        create_iacs_test_session_with_uuid(&mut conn, user_id, asset_id, "waiting_client").await;

    let updated = unwrap_ok!(
        vauban_web::ipc::proxy_iacs::persist_ews_connected(
            &app.db_pool,
            &session_uuid.to_string(),
            Some("203.0.113.50"),
            false,
            "",
        )
        .await
    );
    assert!(updated, "persist_ews_connected must report a row update");

    use vauban_web::schema::proxy_sessions;
    let (status_value, connected_at, client_ip, recording_path): (
        String,
        Option<chrono::DateTime<chrono::Utc>>,
        ipnetwork::IpNetwork,
        Option<String>,
    ) = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::uuid.eq(session_uuid))
            .select((
                proxy_sessions::status,
                proxy_sessions::connected_at,
                proxy_sessions::client_ip,
                proxy_sessions::recording_path,
            ))
            .first(&mut conn)
            .await
    );
    assert_eq!(status_value, "ews_connected");
    assert!(
        connected_at.is_some(),
        "connected_at MUST be anchored at the SSH auth"
    );
    assert_eq!(client_ip.ip().to_string(), "203.0.113.50");
    assert!(
        recording_path.is_none(),
        "recording disabled: recording_path must NOT be set"
    );
}

/// When IACS recording is enabled, the `ews_connected` transition
/// MUST set `is_recorded` + `recording_path` immediately: a
/// zero-channel session already points at its audit manifest.
#[tokio::test]
async fn persist_ews_connected_sets_recording_fields_when_enabled() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_id = create_simple_admin_user(&mut conn, &unique_name("ews_rec_admin")).await;
    let user_id = create_simple_user(&mut conn, &unique_name("ews_rec_user")).await;
    let asset_id =
        create_simple_iacs_asset(&mut conn, &unique_name("ews-rec-iacs"), admin_id).await;
    let (_, session_uuid) =
        create_iacs_test_session_with_uuid(&mut conn, user_id, asset_id, "waiting_client").await;

    let updated = unwrap_ok!(
        vauban_web::ipc::proxy_iacs::persist_ews_connected(
            &app.db_pool,
            &session_uuid.to_string(),
            None,
            true,
            "/var/vauban/recordings",
        )
        .await
    );
    assert!(updated);

    use vauban_web::schema::proxy_sessions;
    let (is_recorded, recording_path): (bool, Option<String>) = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::uuid.eq(session_uuid))
            .select((proxy_sessions::is_recorded, proxy_sessions::recording_path))
            .first(&mut conn)
            .await
    );
    assert!(is_recorded, "recording enabled: is_recorded must flip");
    let path = recording_path.expect("recording_path must be set at auth");
    assert!(
        path.starts_with("/var/vauban/recordings") && path.contains(&session_uuid.to_string()),
        "recording_path must be anchored under the storage path with \
         the session uuid, got {path}"
    );
}

/// Idempotence + rank monotonicity: a re-delivered `ews_connected`
/// is a no-op (first `connected_at` wins), and a LATE arrival after
/// `tunnel_active` cannot demote the row.
#[tokio::test]
async fn persist_ews_connected_is_idempotent_and_never_demotes() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_id = create_simple_admin_user(&mut conn, &unique_name("ews_idem_admin")).await;
    let user_id = create_simple_user(&mut conn, &unique_name("ews_idem_user")).await;
    let asset_id =
        create_simple_iacs_asset(&mut conn, &unique_name("ews-idem-iacs"), admin_id).await;
    let (_, session_uuid) =
        create_iacs_test_session_with_uuid(&mut conn, user_id, asset_id, "waiting_client").await;

    let first = unwrap_ok!(
        vauban_web::ipc::proxy_iacs::persist_ews_connected(
            &app.db_pool,
            &session_uuid.to_string(),
            Some("198.51.100.20"),
            false,
            "",
        )
        .await
    );
    assert!(first);

    use vauban_web::schema::proxy_sessions;
    let connected_after_first: Option<chrono::DateTime<chrono::Utc>> = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::uuid.eq(session_uuid))
            .select(proxy_sessions::connected_at)
            .first(&mut conn)
            .await
    );

    let second = unwrap_ok!(
        vauban_web::ipc::proxy_iacs::persist_ews_connected(
            &app.db_pool,
            &session_uuid.to_string(),
            Some("198.51.100.99"),
            false,
            "",
        )
        .await
    );
    assert!(!second, "re-delivery MUST be a no-op");

    // Promote to tunnel_active, then replay ews_connected: the row
    // must stay active (rank-monotone lifecycle).
    let promoted = unwrap_ok!(
        vauban_web::ipc::proxy_iacs::persist_tunnel_active(
            &app.db_pool,
            &session_uuid.to_string(),
            None,
        )
        .await
    );
    assert!(promoted, "ews_connected -> tunnel_active must succeed");
    let late = unwrap_ok!(
        vauban_web::ipc::proxy_iacs::persist_ews_connected(
            &app.db_pool,
            &session_uuid.to_string(),
            None,
            false,
            "",
        )
        .await
    );
    assert!(!late, "a late ews_connected must not demote an active row");

    let (status_value, connected_final): (String, Option<chrono::DateTime<chrono::Utc>>) = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::uuid.eq(session_uuid))
            .select((proxy_sessions::status, proxy_sessions::connected_at))
            .first(&mut conn)
            .await
    );
    assert_eq!(status_value, "tunnel_active");
    assert_eq!(
        connected_after_first, connected_final,
        "connected_at MUST stay anchored to the SSH-auth transition \
         across the whole lifecycle (COALESCE in persist_tunnel_active)"
    );
}

// ===================================================================
// 1. tunnel_active path
// ===================================================================

/// Receiving `IacsTunnelStatusUpdate { status = "tunnel_active",
/// peer_ip = Some(<EWS IP>) }` MUST flip the row from
/// `waiting_client` to `tunnel_active`, anchor `connected_at`, and
/// overwrite `client_ip` with the EWS source.
#[tokio::test]
async fn persist_tunnel_active_flips_waiting_client_to_tunnel_active() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_username = unique_name("persist_active_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username).await;
    let user_id = create_simple_user(&mut conn, "persist_active_user").await;
    let asset_id =
        create_simple_iacs_asset(&mut conn, &unique_name("persist-active-iacs"), admin_id).await;

    let (_, session_uuid) =
        create_iacs_test_session_with_uuid(&mut conn, user_id, asset_id, "waiting_client").await;

    let updated = unwrap_ok!(
        vauban_web::ipc::proxy_iacs::persist_tunnel_active(
            &app.db_pool,
            &session_uuid.to_string(),
            Some("203.0.113.42"),
        )
        .await
    );
    assert!(updated, "persist_tunnel_active must report a row update");

    use vauban_web::schema::proxy_sessions;
    let (status_value, connected_at, client_ip): (
        String,
        Option<chrono::DateTime<chrono::Utc>>,
        ipnetwork::IpNetwork,
    ) = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::uuid.eq(session_uuid))
            .select((
                proxy_sessions::status,
                proxy_sessions::connected_at,
                proxy_sessions::client_ip,
            ))
            .first(&mut conn)
            .await
    );
    assert_eq!(status_value, "tunnel_active");
    assert!(
        connected_at.is_some(),
        "connected_at MUST be anchored when the row flips active"
    );
    assert_eq!(
        client_ip.ip().to_string(),
        "203.0.113.42",
        "client_ip MUST be overwritten with the EWS peer IP"
    );
}

/// `peer_ip = None` MUST flip status + `connected_at` but leave
/// `client_ip` untouched (preserves the WebUI browser IP captured
/// at session creation time).
#[tokio::test]
async fn persist_tunnel_active_without_peer_ip_preserves_existing_client_ip() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_username = unique_name("no_peer_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username).await;
    let user_id = create_simple_user(&mut conn, "no_peer_user").await;
    let asset_id =
        create_simple_iacs_asset(&mut conn, &unique_name("no-peer-iacs"), admin_id).await;
    let (_, session_uuid) =
        create_iacs_test_session_with_uuid(&mut conn, user_id, asset_id, "waiting_client").await;

    use vauban_web::schema::proxy_sessions;
    let original_ip: ipnetwork::IpNetwork = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::uuid.eq(session_uuid))
            .select(proxy_sessions::client_ip)
            .first(&mut conn)
            .await
    );

    let updated = unwrap_ok!(
        vauban_web::ipc::proxy_iacs::persist_tunnel_active(
            &app.db_pool,
            &session_uuid.to_string(),
            None,
        )
        .await
    );
    assert!(updated);

    let (status_value, client_ip): (String, ipnetwork::IpNetwork) = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::uuid.eq(session_uuid))
            .select((proxy_sessions::status, proxy_sessions::client_ip))
            .first(&mut conn)
            .await
    );
    assert_eq!(status_value, "tunnel_active");
    assert_eq!(
        client_ip, original_ip,
        "client_ip MUST be left untouched when the proxy does not \
         report a peer_ip"
    );
}

/// Idempotent: a second `tunnel_active` notification on a row that
/// is already `tunnel_active` MUST NOT touch the row (the first
/// `connected_at` is the one we want to display).
#[tokio::test]
async fn persist_tunnel_active_is_idempotent_against_redelivery() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_username = unique_name("idem_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username).await;
    let user_id = create_simple_user(&mut conn, "idem_user").await;
    let asset_id = create_simple_iacs_asset(&mut conn, &unique_name("idem-iacs"), admin_id).await;
    let (_, session_uuid) =
        create_iacs_test_session_with_uuid(&mut conn, user_id, asset_id, "waiting_client").await;

    let first = unwrap_ok!(
        vauban_web::ipc::proxy_iacs::persist_tunnel_active(
            &app.db_pool,
            &session_uuid.to_string(),
            Some("198.51.100.7"),
        )
        .await
    );
    assert!(first, "first call MUST update");

    use vauban_web::schema::proxy_sessions;
    let connected_after_first: Option<chrono::DateTime<chrono::Utc>> = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::uuid.eq(session_uuid))
            .select(proxy_sessions::connected_at)
            .first(&mut conn)
            .await
    );

    let second = unwrap_ok!(
        vauban_web::ipc::proxy_iacs::persist_tunnel_active(
            &app.db_pool,
            &session_uuid.to_string(),
            Some("198.51.100.99"),
        )
        .await
    );
    assert!(
        !second,
        "second call MUST be a no-op once the row is already active \
         (the filter is gated on the pre-active statuses \
         `waiting_client` / `ews_connected`)"
    );

    let (connected_after_second, client_ip): (
        Option<chrono::DateTime<chrono::Utc>>,
        ipnetwork::IpNetwork,
    ) = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::uuid.eq(session_uuid))
            .select((proxy_sessions::connected_at, proxy_sessions::client_ip))
            .first(&mut conn)
            .await
    );
    assert_eq!(
        connected_after_first, connected_after_second,
        "connected_at MUST stay anchored to the first transition"
    );
    assert_eq!(
        client_ip.ip().to_string(),
        "198.51.100.7",
        "client_ip MUST stay at the FIRST peer_ip (no late re-write)"
    );
}

// ===================================================================
// 2. terminated path
// ===================================================================

/// `IacsTunnelClosed` MUST flip a `tunnel_active` row to
/// `terminated` and anchor `disconnected_at`.
#[tokio::test]
async fn persist_tunnel_closed_flips_tunnel_active_to_terminated() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_username = unique_name("closed_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username).await;
    let user_id = create_simple_user(&mut conn, "closed_user").await;
    let asset_id = create_simple_iacs_asset(&mut conn, &unique_name("closed-iacs"), admin_id).await;
    let (_, session_uuid) =
        create_iacs_test_session_with_uuid(&mut conn, user_id, asset_id, "tunnel_active").await;

    let updated = unwrap_ok!(
        vauban_web::ipc::proxy_iacs::persist_tunnel_closed(
            &app.db_pool,
            &session_uuid.to_string(),
            false,
            "",
        )
        .await
    );
    assert!(updated);

    use vauban_web::schema::proxy_sessions;
    let (status_value, disconnected_at): (String, Option<chrono::DateTime<chrono::Utc>>) = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::uuid.eq(session_uuid))
            .select((proxy_sessions::status, proxy_sessions::disconnected_at,))
            .first(&mut conn)
            .await
    );
    assert_eq!(status_value, "terminated");
    assert!(disconnected_at.is_some());
}

/// `IacsTunnelClosed` arriving on a `waiting_client` row (the EWS
/// disconnected before any byte flowed) MUST also flip to
/// `terminated`. Otherwise an orphan stays around forever.
#[tokio::test]
async fn persist_tunnel_closed_handles_waiting_client_orphan() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_username = unique_name("orphan_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username).await;
    let user_id = create_simple_user(&mut conn, "orphan_user").await;
    let asset_id = create_simple_iacs_asset(&mut conn, &unique_name("orphan-iacs"), admin_id).await;
    let (_, session_uuid) =
        create_iacs_test_session_with_uuid(&mut conn, user_id, asset_id, "waiting_client").await;

    let updated = unwrap_ok!(
        vauban_web::ipc::proxy_iacs::persist_tunnel_closed(
            &app.db_pool,
            &session_uuid.to_string(),
            false,
            "",
        )
        .await
    );
    assert!(updated);

    use vauban_web::schema::proxy_sessions;
    let status_value: String = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::uuid.eq(session_uuid))
            .select(proxy_sessions::status)
            .first(&mut conn)
            .await
    );
    assert_eq!(status_value, "terminated");
}

/// `IacsTunnelClosed` arriving on an `ews_connected` row (the EWS
/// authenticated then disconnected without ever opening a channel)
/// MUST flip to `terminated` -- the zero-channel audit-trail path.
#[tokio::test]
async fn persist_tunnel_closed_handles_ews_connected_zero_channel_login() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_id = create_simple_admin_user(&mut conn, &unique_name("zc_admin")).await;
    let user_id = create_simple_user(&mut conn, &unique_name("zc_user")).await;
    let asset_id = create_simple_iacs_asset(&mut conn, &unique_name("zc-iacs"), admin_id).await;
    let (_, session_uuid) =
        create_iacs_test_session_with_uuid(&mut conn, user_id, asset_id, "waiting_client").await;
    let flipped = unwrap_ok!(
        vauban_web::ipc::proxy_iacs::persist_ews_connected(
            &app.db_pool,
            &session_uuid.to_string(),
            None,
            false,
            "",
        )
        .await
    );
    assert!(flipped);

    let updated = unwrap_ok!(
        vauban_web::ipc::proxy_iacs::persist_tunnel_closed(
            &app.db_pool,
            &session_uuid.to_string(),
            false,
            "",
        )
        .await
    );
    assert!(updated, "ews_connected rows must be closeable");

    use vauban_web::schema::proxy_sessions;
    let (status_value, disconnected_at): (String, Option<chrono::DateTime<chrono::Utc>>) = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::uuid.eq(session_uuid))
            .select((proxy_sessions::status, proxy_sessions::disconnected_at))
            .first(&mut conn)
            .await
    );
    assert_eq!(status_value, "terminated");
    assert!(disconnected_at.is_some());
}

/// Idempotent: re-delivery on an already-terminated row MUST be a
/// silent no-op.
#[tokio::test]
async fn persist_tunnel_closed_is_idempotent() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_username = unique_name("idem_close_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username).await;
    let user_id = create_simple_user(&mut conn, "idem_close_user").await;
    let asset_id =
        create_simple_iacs_asset(&mut conn, &unique_name("idem-close-iacs"), admin_id).await;
    let (_, session_uuid) =
        create_iacs_test_session_with_uuid(&mut conn, user_id, asset_id, "tunnel_active").await;

    let first = unwrap_ok!(
        vauban_web::ipc::proxy_iacs::persist_tunnel_closed(
            &app.db_pool,
            &session_uuid.to_string(),
            false,
            "",
        )
        .await
    );
    assert!(first);

    let second = unwrap_ok!(
        vauban_web::ipc::proxy_iacs::persist_tunnel_closed(
            &app.db_pool,
            &session_uuid.to_string(),
            false,
            "",
        )
        .await
    );
    assert!(
        !second,
        "re-delivery MUST be a no-op once the row is already terminated"
    );
}

// ===================================================================
// 3. Unknown / malformed UUID
// ===================================================================

/// A malformed session UUID MUST surface as a validation error
/// (caller-side typo or test mistake), not a panic and not a
/// silent UPDATE on an unrelated row.
#[tokio::test]
async fn persist_helpers_reject_invalid_session_uuid() {
    let app = TestApp::spawn().await;

    let active_err = vauban_web::ipc::proxy_iacs::persist_tunnel_active(
        &app.db_pool,
        "not-a-uuid",
        Some("203.0.113.1"),
    )
    .await;
    assert!(active_err.is_err());

    let closed_err =
        vauban_web::ipc::proxy_iacs::persist_tunnel_closed(&app.db_pool, "not-a-uuid", false, "")
            .await;
    assert!(closed_err.is_err());
}

/// A well-formed UUID that does not match any row MUST simply
/// return `Ok(false)` (the IPC pump treats this as "session
/// already gone"), not error.
#[tokio::test]
async fn persist_helpers_return_false_on_unknown_uuid() {
    let app = TestApp::spawn().await;
    let unknown = uuid::Uuid::new_v4().to_string();

    let active = unwrap_ok!(
        vauban_web::ipc::proxy_iacs::persist_tunnel_active(
            &app.db_pool,
            &unknown,
            Some("203.0.113.10"),
        )
        .await
    );
    assert!(!active);

    let closed = unwrap_ok!(
        vauban_web::ipc::proxy_iacs::persist_tunnel_closed(&app.db_pool, &unknown, false, "").await
    );
    assert!(!closed);
}
