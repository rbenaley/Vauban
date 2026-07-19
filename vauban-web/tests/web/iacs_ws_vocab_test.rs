//! IACS SessionLive WebSocket vocabulary — anti-drift suite.
//!
//! July 2026 incident: two emitters push IACS lifecycle events on
//! `WsChannel::SessionLive(<uuid>)` — the in-process dev sshd
//! (`services/iacs_tunnel/server.rs`) and the production privsep
//! pump (`ipc/proxy_iacs.rs`). The proxy pump used a divergent
//! envelope (`type: "iacs_tunnel_status"` + `status` field) that the
//! Alpine `iacsTunnelStatus` component never understood, so in
//! production the status page NEVER reacted: the waiting-client
//! countdown kept ticking over an established tunnel, and at zero it
//! flipped to a false "expired" pill. Invisible pre-CSP-fix because
//! the component lived in an inline `<script>` the CSP blocked.
//!
//! The fix centralizes the vocabulary in
//! `services::iacs_tunnel::ws_vocab` (constants + a pure Rust twin
//! of the client state machine, proptest-covered in-crate). This
//! file locks the seams:
//!
//! * **JS/Rust lock-step pins** — the component handles every
//!   canonical type and carries the terminated-absorbing guard.
//! * **Source drift pins** — the legacy envelope cannot reappear in
//!   either emitter; both reference `ws_vocab`.
//! * **E2E (privsep path)** — a real `ProxyIacsClient` pump fed
//!   through a real pipe pair: `IacsTunnelStatusUpdate` /
//!   `IacsTunnelClosed` IPC messages must surface on the broadcast
//!   channel with the canonical `type` AND flip the DB row. This is
//!   exactly the test that would have caught the incident.
//!
//! The in-process emitter's E2E lives in
//! `iacs_tunnel_status_ux_test.rs` (full russh handshake); this file
//! covers the proxy flavour without spawning a subprocess.

use std::time::Duration;

use serial_test::serial;
use tokio::time::timeout;

use crate::common::{TestApp, unwrap_ok};
use crate::fixtures::{
    create_iacs_test_session_with_uuid, create_simple_admin_user, create_simple_iacs_asset,
    create_simple_user, unique_name,
};
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::RunQueryDsl;
use vauban_web::services::broadcast::WsChannel;
use vauban_web::services::iacs_tunnel::ws_vocab;

// =============================================================================
// Section A. JS / Rust model lock-step pins.
// =============================================================================

fn components_js() -> &'static str {
    include_str!("../../static/js/vauban-components.js")
}

/// The Alpine component must branch on EVERY canonical wire type.
/// A missing branch silently re-creates the incident for that event.
#[test]
fn js_component_handles_every_canonical_type() {
    let js = components_js();
    for t in ws_vocab::ALL_TYPES {
        let needle = format!("msg.type === '{t}'");
        assert!(
            js.contains(&needle),
            "vauban-components.js must handle wire type `{t}` (missing `{needle}`); \
             the Rust transition table lives in services/iacs_tunnel/ws_vocab.rs \
             and MUST stay in lock-step"
        );
    }
}

/// The legacy envelope types must never be handled NOR emitted again:
/// they are dead vocabulary. If a future refactor reintroduces them,
/// the component and the emitters drift apart silently.
#[test]
fn legacy_envelope_types_are_gone_everywhere() {
    let js = components_js();
    let proxy_pump = include_str!("../../src/ipc/proxy_iacs.rs");
    for legacy in ["iacs_tunnel_status", "iacs_tunnel_closed"] {
        let quoted = format!("\"{legacy}\"");
        assert!(
            !proxy_pump.contains(&quoted),
            "ipc/proxy_iacs.rs must not emit the legacy `{legacy}` envelope \
             (use services::iacs_tunnel::ws_vocab constants)"
        );
        let js_needle = format!("'{legacy}'");
        assert!(
            !js.contains(&js_needle),
            "vauban-components.js must not reference the legacy `{legacy}` type"
        );
    }
}

/// Both emitters must reference the canonical vocabulary module, so
/// a new event type necessarily lands in `ws_vocab` first (where the
/// transition model and its proptests live).
#[test]
fn both_emitters_reference_ws_vocab() {
    let proxy_pump = include_str!("../../src/ipc/proxy_iacs.rs");
    let inprocess = include_str!("../../src/services/iacs_tunnel/server.rs");
    assert!(
        proxy_pump.contains("ws_vocab::"),
        "ipc/proxy_iacs.rs must build SessionLive payload types from ws_vocab"
    );
    assert!(
        inprocess.contains("ws_vocab::"),
        "services/iacs_tunnel/server.rs must build SessionLive payload types from ws_vocab"
    );
}

/// The two battle-hardening guards added with the fix must survive
/// refactors: terminated is absorbing, and a re-delivered activation
/// must not reset the duration anchor.
#[test]
fn js_component_pins_absorbing_and_idempotence_guards() {
    let js = components_js();
    assert!(
        js.contains("if (this.status === 'terminated') return;"),
        "iacsTunnelStatus must ignore tunnel_active after the authoritative \
         close (terminated is absorbing — see ws_vocab::ClientState)"
    );
    assert!(
        js.contains("if (this.status !== 'tunnel_active')"),
        "iacsTunnelStatus must not reset startedAt on a re-delivered \
         tunnel_active (idempotence — see ws_vocab proptest invariant 4)"
    );
}

// =============================================================================
// Section B. E2E — privsep pump: IPC in, canonical WS frame + DB flip out.
// =============================================================================

/// Spawn a real `ProxyIacsClient` pump wired to the TestApp's
/// broadcast + DB, and return the proxy-side channel used to inject
/// IPC messages (playing the role of vauban-proxy-iacs).
fn spawn_proxy_pump(app: &TestApp) -> shared::ipc::IpcChannel {
    let (web_side, proxy_side) = shared::ipc::IpcChannel::pair().expect("ipc pair");
    let read_fd = web_side.read_fd();
    let write_fd = web_side.write_fd();
    // The client wraps the fds in its own IpcChannel (from_raw_fds
    // takes ownership); forget the original handle so the fds are
    // not double-closed on drop.
    std::mem::forget(web_side);
    let client = vauban_web::ipc::proxy_iacs::ProxyIacsClient::new(read_fd, write_fd)
        .expect("proxy iacs client");
    let broadcast = app.broadcast.clone();
    let pool = app.db_pool.clone();
    let state = app.app_state.clone();
    tokio::spawn(async move {
        let _ = client
            .process_incoming_with_state(broadcast, pool, state)
            .await;
    });
    proxy_side
}

/// Full activation path: `IacsTunnelStatusUpdate { status =
/// "tunnel_active" }` from the proxy must fan out a frame the Alpine
/// component actually understands (`type: "tunnel_active"`, the
/// incident regression) AND flip the `proxy_sessions` row.
#[tokio::test]
#[serial]
async fn proxy_pump_emits_canonical_tunnel_active_frame_and_flips_row() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_id = create_simple_admin_user(&mut conn, &unique_name("wsvocab_a")).await;
    let user_id = create_simple_user(&mut conn, &unique_name("wsvocab_u")).await;
    let asset_id =
        create_simple_iacs_asset(&mut conn, &unique_name("wsvocab-iacs"), admin_id).await;
    let (_, session_uuid) =
        create_iacs_test_session_with_uuid(&mut conn, user_id, asset_id, "waiting_client").await;

    // Subscribe BEFORE injecting the IPC message.
    let channel = WsChannel::SessionLive(session_uuid.to_string());
    let mut rx = app.broadcast.subscribe(&channel).await;

    let proxy_side = spawn_proxy_pump(app);
    proxy_side
        .send(&shared::messages::Message::IacsTunnelStatusUpdate {
            session_id: session_uuid.to_string(),
            status: "tunnel_active".to_string(),
            bytes_in: 0,
            bytes_out: 0,
            peer_ip: Some("203.0.113.77".to_string()),
        })
        .expect("send IacsTunnelStatusUpdate");

    let frame = timeout(Duration::from_secs(3), rx.recv())
        .await
        .expect("timed out waiting for the tunnel_active frame")
        .expect("broadcast recv");
    let parsed: serde_json::Value = serde_json::from_str(&frame).expect("frame is JSON");

    // THE incident regression: the frame type must be the canonical
    // vocabulary the JS component branches on, not the legacy
    // `iacs_tunnel_status` envelope.
    assert_eq!(
        parsed["type"],
        ws_vocab::TYPE_TUNNEL_ACTIVE,
        "privsep frame must use the canonical type (got: {frame})"
    );
    assert_eq!(parsed["peer_ip"], "203.0.113.77");

    // And the model must accept it: waiting + this frame = active,
    // countdown stopped (the user-visible symptom).
    let model = ws_vocab::ClientState::initial("waiting_client", 300)
        .apply_event(parsed["type"].as_str().expect("type is a string"));
    assert_eq!(model.status, ws_vocab::ClientStatus::TunnelActive);
    assert!(!model.countdown_running);

    // DB flip (same seam, one observation point further).
    use vauban_web::schema::proxy_sessions;
    let status_value: String = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::uuid.eq(session_uuid))
            .select(proxy_sessions::status)
            .first(&mut conn)
            .await
    );
    assert_eq!(status_value, "tunnel_active");
}

/// Close path: `IacsTunnelClosed` must fan out the canonical
/// `tunnel_closed` frame (with final byte counters) and terminate
/// the row.
#[tokio::test]
#[serial]
async fn proxy_pump_emits_canonical_tunnel_closed_frame_and_terminates_row() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_id = create_simple_admin_user(&mut conn, &unique_name("wsvocab_ca")).await;
    let user_id = create_simple_user(&mut conn, &unique_name("wsvocab_cu")).await;
    let asset_id =
        create_simple_iacs_asset(&mut conn, &unique_name("wsvocab-close"), admin_id).await;
    let (_, session_uuid) =
        create_iacs_test_session_with_uuid(&mut conn, user_id, asset_id, "tunnel_active").await;

    let channel = WsChannel::SessionLive(session_uuid.to_string());
    let mut rx = app.broadcast.subscribe(&channel).await;

    let proxy_side = spawn_proxy_pump(app);
    proxy_side
        .send(&shared::messages::Message::IacsTunnelClosed {
            request_id: 1,
            session_id: session_uuid.to_string(),
            reason: "ews_disconnect".to_string(),
            bytes_in: 1234,
            bytes_out: 5678,
            peer_ip: None,
        })
        .expect("send IacsTunnelClosed");

    let frame = timeout(Duration::from_secs(3), rx.recv())
        .await
        .expect("timed out waiting for the tunnel_closed frame")
        .expect("broadcast recv");
    let parsed: serde_json::Value = serde_json::from_str(&frame).expect("frame is JSON");

    assert_eq!(
        parsed["type"],
        ws_vocab::TYPE_TUNNEL_CLOSED,
        "privsep close frame must use the canonical type (got: {frame})"
    );
    assert_eq!(parsed["bytes_in"], 1234);
    assert_eq!(parsed["bytes_out"], 5678);

    // Model: active + closed frame = terminated, all timers stopped.
    let model = ws_vocab::ClientState::initial("tunnel_active", -1)
        .apply_event(parsed["type"].as_str().expect("type is a string"));
    assert_eq!(model.status, ws_vocab::ClientStatus::Terminated);
    assert!(!model.duration_running);

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

/// The production stats tick (July 2026, byte counters stuck at
/// zero): `IacsTunnelStatusUpdate { status = "tunnel_stats" }`
/// emitted every 5 s by vauban-proxy-iacs' per-login ticker must
/// surface as a canonical `tunnel_stats` frame carrying the byte
/// counters, without any lifecycle transition and without touching
/// the DB row.
#[tokio::test]
#[serial]
async fn proxy_pump_relays_periodic_tunnel_stats_frames() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_id = create_simple_admin_user(&mut conn, &unique_name("wsvocab_ta")).await;
    let user_id = create_simple_user(&mut conn, &unique_name("wsvocab_tu")).await;
    let asset_id =
        create_simple_iacs_asset(&mut conn, &unique_name("wsvocab-tick"), admin_id).await;
    let (_, session_uuid) =
        create_iacs_test_session_with_uuid(&mut conn, user_id, asset_id, "tunnel_active").await;

    let channel = WsChannel::SessionLive(session_uuid.to_string());
    let mut rx = app.broadcast.subscribe(&channel).await;

    let proxy_side = spawn_proxy_pump(app);
    proxy_side
        .send(&shared::messages::Message::IacsTunnelStatusUpdate {
            session_id: session_uuid.to_string(),
            status: "tunnel_stats".to_string(),
            bytes_in: 9000,
            bytes_out: 4500,
            peer_ip: None,
        })
        .expect("send IacsTunnelStatusUpdate");

    let frame = timeout(Duration::from_secs(3), rx.recv())
        .await
        .expect("timed out waiting for the tunnel_stats frame")
        .expect("broadcast recv");
    let parsed: serde_json::Value = serde_json::from_str(&frame).expect("frame is JSON");
    assert_eq!(parsed["type"], ws_vocab::TYPE_TUNNEL_STATS);
    assert_eq!(parsed["bytes_in"], 9000);
    assert_eq!(parsed["bytes_out"], 4500);

    // No lifecycle transition: the pill stays on tunnel_active.
    let model = ws_vocab::ClientState::initial("tunnel_active", -1)
        .apply_event(parsed["type"].as_str().expect("type is a string"));
    assert_eq!(model.status, ws_vocab::ClientStatus::TunnelActive);
    assert!(model.duration_running);

    // And no DB write: stats are ephemeral.
    use vauban_web::schema::proxy_sessions;
    let status_value: String = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::uuid.eq(session_uuid))
            .select(proxy_sessions::status)
            .first(&mut conn)
            .await
    );
    assert_eq!(status_value, "tunnel_active");
}

/// Battle case: an unknown / future status string from the proxy
/// must surface as a stats frame (fail-safe) — the client model
/// treats it as byte counters only, so no lifecycle transition can
/// be forged. The DB row is untouched.
#[tokio::test]
#[serial]
async fn proxy_pump_demotes_unknown_status_to_stats_frame() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_id = create_simple_admin_user(&mut conn, &unique_name("wsvocab_sa")).await;
    let user_id = create_simple_user(&mut conn, &unique_name("wsvocab_su")).await;
    let asset_id =
        create_simple_iacs_asset(&mut conn, &unique_name("wsvocab-stats"), admin_id).await;
    let (_, session_uuid) =
        create_iacs_test_session_with_uuid(&mut conn, user_id, asset_id, "waiting_client").await;

    let channel = WsChannel::SessionLive(session_uuid.to_string());
    let mut rx = app.broadcast.subscribe(&channel).await;

    let proxy_side = spawn_proxy_pump(app);
    proxy_side
        .send(&shared::messages::Message::IacsTunnelStatusUpdate {
            session_id: session_uuid.to_string(),
            status: "some_future_status".to_string(),
            bytes_in: 42,
            bytes_out: 7,
            peer_ip: None,
        })
        .expect("send IacsTunnelStatusUpdate");

    let frame = timeout(Duration::from_secs(3), rx.recv())
        .await
        .expect("timed out waiting for the stats frame")
        .expect("broadcast recv");
    let parsed: serde_json::Value = serde_json::from_str(&frame).expect("frame is JSON");
    assert_eq!(parsed["type"], ws_vocab::TYPE_TUNNEL_STATS);
    assert_eq!(parsed["bytes_in"], 42);

    // No lifecycle transition client-side...
    let model = ws_vocab::ClientState::initial("waiting_client", 300)
        .apply_event(parsed["type"].as_str().expect("type is a string"));
    assert_eq!(model.status, ws_vocab::ClientStatus::WaitingClient);
    assert!(model.countdown_running, "countdown keeps running");

    // ...and none server-side either.
    use vauban_web::schema::proxy_sessions;
    let status_value: String = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::uuid.eq(session_uuid))
            .select(proxy_sessions::status)
            .first(&mut conn)
            .await
    );
    assert_eq!(status_value, "waiting_client");
}
