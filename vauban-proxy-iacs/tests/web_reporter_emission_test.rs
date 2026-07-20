//! Pin tests for the `WebReporter` IPC emission contract added in
//! 0.7.12 (issue: active sessions surfaces stuck on `waiting_client`
//! because `vauban-proxy-iacs` never sent `IacsTunnelStatusUpdate`
//! / `IacsTunnelClosed` back to vauban-web).
//!
//! Drift from the contract -- e.g. dropping the `tunnel_active`
//! emission, sending the `IacsTunnelClosed` for a session that never
//! reached `direct-tcpip`, or losing the single-writer-task
//! serialisation that protects the web pipe fd -- silently breaks
//! the operator-facing surfaces (`/sessions/active`, Bastion Watch
//! dashboard, `/sessions` history). These tests grep the production
//! source so the regression is caught BEFORE the proxy is restarted
//! in production.
//!
//! Functional behaviour (hand-shake with russh, tokio::join on the
//! relay tasks, etc.) is exercised by the existing
//! `per_asset_target_test.rs` suite; here we only pin the call
//! graph.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

const SRC: &str = "src";

fn read_src(rel: &str) -> String {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(SRC)
        .join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {}", p.display(), e))
}

/// The russh handler MUST emit `Message::IacsTunnelStatusUpdate {
/// status = "tunnel_active", peer_ip }` once per EWS login on the
/// first successful `direct-tcpip` channel open. Without it the
/// vauban-web IPC pump never flips `proxy_sessions.status` from
/// `waiting_client` to `tunnel_active`, the SQL filter for
/// `/sessions/active` collapses to zero rows, and the Bastion Watch
/// IACS counter stays at zero.
#[test]
fn handler_emits_iacs_tunnel_status_update_on_first_channel_open() {
    let src = read_src("server.rs");
    assert!(
        src.contains("Message::IacsTunnelStatusUpdate {"),
        "server.rs MUST construct an IacsTunnelStatusUpdate IPC \
         (active-list integration would otherwise stay dormant)"
    );
    assert!(
        src.contains("status: \"tunnel_active\".to_string()"),
        "server.rs MUST tag the IacsTunnelStatusUpdate as `tunnel_active` \
         so `persist_tunnel_active` flips the DB row"
    );
    assert!(
        src.contains("tunnel_active_emitted.swap(true"),
        "server.rs MUST guard the emission behind a one-shot \
         `tunnel_active_emitted` flag so a multi-channel EWS login \
         does not drown the IPC bus with redundant status updates"
    );
    assert!(
        src.contains("self.peer_addr.map(|sa| sa.ip().to_string())"),
        "server.rs MUST populate the `peer_ip` field of the \
         IacsTunnelStatusUpdate so vauban-web can persist the EWS \
         source IP into proxy_sessions.client_ip"
    );
}

/// On handler drop (the EWS SSH connection ends) the proxy MUST
/// emit `Message::IacsTunnelClosed` so vauban-web can flip the row
/// to `terminated`, anchor `disconnected_at`, and remove it from
/// the active sessions surfaces. Fires as soon as an
/// `ews_connected` was emitted (the SSH handshake succeeded): an
/// authenticated login that never opened a `direct-tcpip` channel
/// still has a live `ews_connected` row to close. A connection that
/// never authenticated was never persisted past `waiting_client`,
/// so there is nothing to close.
#[test]
fn handler_emits_iacs_tunnel_closed_on_drop() {
    let src = read_src("server.rs");
    assert!(
        src.contains("Message::IacsTunnelClosed {"),
        "server.rs MUST emit IacsTunnelClosed at handler-drop time"
    );
    assert!(
        src.contains("self.ews_connected_emitted.load(Ordering::SeqCst)"),
        "server.rs MUST gate the IacsTunnelClosed emission on the \
         `ews_connected_emitted` flag: an authenticated zero-channel \
         login still terminates its row, while a failed-auth \
         connection (never persisted past waiting_client) does not \
         generate a spurious close event"
    );
    assert!(
        src.contains("reason: \"ews_disconnect\""),
        "server.rs MUST tag the drop-time IacsTunnelClosed reason \
         as `ews_disconnect` so operators can distinguish a clean \
         EWS shutdown from a server-initiated terminate"
    );
}

/// `auth_succeeded` MUST emit the one-shot `IacsTunnelStatusUpdate
/// { status = "ews_connected", peer_ip }`: the SSH handshake is an
/// authenticated presence on the bastion even before the first
/// `direct-tcpip`, and vauban-web needs it to flip the row, anchor
/// `connected_at` / `client_ip`, and surface the session (with its
/// Terminate button) on `/sessions/active`.
#[test]
fn auth_succeeded_emits_one_shot_ews_connected() {
    let src = read_src("server.rs");
    assert!(
        src.contains("status: \"ews_connected\".to_string()"),
        "server.rs MUST tag the auth-time IacsTunnelStatusUpdate as \
         `ews_connected` so `persist_ews_connected` flips the DB row"
    );
    assert!(
        src.contains("ews_connected_emitted.swap(true"),
        "server.rs MUST guard the ews_connected emission behind a \
         one-shot `ews_connected_emitted` flag (re-auth on the same \
         connection must not re-emit)"
    );
    // The recording/DB wall-clock anchor is captured at auth (the
    // ews_connected transition), matching `connected_at` in the DB.
    let auth_zone = src
        .split("async fn auth_succeeded")
        .nth(1)
        .and_then(|rest| rest.split("async fn channel_open_session").next())
        .expect("auth_succeeded body present");
    assert!(
        auth_zone.contains("self.connected_at_us.compare_exchange("),
        "auth_succeeded MUST anchor connected_at_us (the recording \
         directory layout must match the DB connected_at set at the \
         ews_connected transition)"
    );
}

/// The relay teardown AND the handler `Drop` both fold per-channel
/// byte counts into the per-EWS-login totals through the ONE-SHOT
/// `TunnelHandle::flush_into` seam (idempotent guard in
/// registry.rs). Two racers exist by design: the teardown task
/// (channel closed cleanly) and the `Drop` (EWS connection died with
/// the teardown still in flight). Ad-hoc `fetch_add` calls in
/// server.rs would reintroduce either the double-count (both flush)
/// or the `IacsTunnelClosed { 0, 0 }` under-count (Drop reads the
/// totals before the teardown flush lands -- the July 2026 bug that
/// reset the status-page counters to zero at disconnect).
#[test]
fn relay_and_drop_flush_byte_counters_through_one_shot_seam() {
    let src = read_src("server.rs");
    assert!(
        src.matches(".flush_into(").count() >= 2,
        "BOTH the relay teardown task and the handler Drop MUST fold \
         channel counters into the login totals via \
         TunnelHandle::flush_into"
    );
    assert!(
        !src.contains("session_total_bytes_in.fetch_add(")
            && !src.contains("session_total_bytes_out.fetch_add("),
        "server.rs MUST NOT fetch_add into the session totals \
         directly; the one-shot flush_into seam is the only writer \
         (double-count / zero-count protection)"
    );
    let registry_src = read_src("registry.rs");
    assert!(
        registry_src.contains("if self.flushed.swap(true, Ordering::SeqCst)"),
        "TunnelHandle::flush_into MUST be guarded by a one-shot \
         swap so concurrent flushers cannot double-count"
    );
}

/// The russh accept loop MUST hand the `WebReporter` (the
/// `mpsc::UnboundedSender<Message>` cloned from `web_tx`) to every
/// new `IacsTunnelServer`. A `None` reporter would silently disable
/// IPC emission and revert the regression.
#[test]
fn accept_loop_threads_web_reporter_into_iacs_tunnel_server() {
    let src = read_src("main.rs");
    assert!(
        src.contains("Some(accept_web_tx.clone())"),
        "main.rs MUST pass the web mpsc sender into IacsTunnelServer::new \
         (`Some(accept_web_tx.clone())`) so the russh handler can emit \
         `IacsTunnelStatusUpdate` and `IacsTunnelClosed`"
    );
}

/// Every concurrent task that writes onto the `web` IPC pipe MUST
/// route through the SAME mpsc channel; a single writer task drains
/// that mpsc and serialises the underlying `AsyncIpcChannel::send`
/// calls. Two concurrent tasks doing direct `web.send(...)` could
/// interleave partial frames on the wire (the IpcChannel encodes
/// length-prefixed messages and is not thread-safe for parallel
/// writes).
#[test]
fn web_ipc_writes_serialised_through_single_writer_task() {
    let src = read_src("main.rs");
    assert!(
        src.contains("mpsc::unbounded_channel::<Message>()"),
        "main.rs MUST allocate an mpsc channel for outbound web messages"
    );
    assert!(
        src.contains("while let Some(msg) = web_rx.recv().await"),
        "main.rs MUST spawn a single writer task that drains web_rx \
         and forwards every message to AsyncIpcChannel::send"
    );
    assert!(
        src.contains("web_tx.send(Message::IacsTunnelOpened"),
        "main.rs MUST route the existing IacsTunnelOpened acknowledgements \
         through the mpsc, not call AsyncIpcChannel::send directly, \
         so they never race with the russh-handler emissions"
    );
    let direct_web_send_count = src.matches("web.send(&Message::").count();
    assert_eq!(
        direct_web_send_count, 0,
        "main.rs MUST NOT call AsyncIpcChannel::send directly on \
         the web pipe (found {direct_web_send_count} occurrences); \
         every emission must go through the mpsc to preserve \
         single-writer-task serialisation"
    );
}

/// The per-EWS-login stats ticker (July 2026: status-page byte
/// counters stuck at zero because the privsep proxy never emitted
/// periodic `tunnel_stats`). The ticker MUST:
/// - be spawned by the SAME one-shot `tunnel_active_emitted` guard
///   as the activation message (one ticker per login, only after
///   the first `direct-tcpip`);
/// - tag its reports `status = "tunnel_stats"` so the vauban-web
///   pump maps them to the canonical stats frame (no lifecycle
///   transition, no DB write);
/// - stop on the `SessionHandles` removal performed by the
///   handler's `Drop` (the same lifecycle signal the terminate IPC
///   relies on);
/// - route its accounting through the invariant-covered pure seam
///   (`stats::cumulative_bytes` + `stats::MonotonicReport`), not
///   ad-hoc arithmetic.
#[test]
fn handler_spawns_stats_ticker_on_first_channel_open() {
    let src = read_src("server.rs");
    assert!(
        src.contains("spawn_stats_ticker(StatsTickerJob {"),
        "channel_open_direct_tcpip MUST spawn the per-login stats \
         ticker (status-page byte counters stay at zero without it)"
    );
    assert!(
        src.contains("status: \"tunnel_stats\".to_string()"),
        "the ticker MUST tag its IacsTunnelStatusUpdate as \
         `tunnel_stats` (any other status would be demoted or, \
         worse, replay `tunnel_active`)"
    );
    assert!(
        src.contains("session_handles.get(&session_uuid).is_none()"),
        "the ticker MUST stop when the handler Drop removes the \
         session from SessionHandles (no leaked 5 s tasks after \
         EWS disconnect)"
    );
    assert!(
        src.contains("crate::stats::cumulative_bytes(")
            && src.contains("crate::stats::MonotonicReport::new()"),
        "the ticker MUST compute its report through the pure \
         `crate::stats` seam (unit + proptest coverage) so the \
         skip-closed / monotonic invariants apply to production"
    );
    assert!(
        src.contains("login_channels\n                .iter()")
            || src.contains("login_channels.iter()"),
        "the ticker MUST sample EVERY live channel of the login \
         (login_channels), NOT the session-keyed TunnelRegistry \
         whose insert() replaces the previous handle -- sampling \
         only the newest channel under-counts every earlier or \
         concurrent one"
    );
}

/// The handler `Drop` MUST close + flush EVERY remaining channel of
/// the login (`login_channels`), not just the newest registry
/// handle: with the normal `ssh -L` workflow every local TCP
/// `accept()` opens a new channel, and only flushing the last one
/// under-counted the `IacsTunnelClosed` totals.
#[test]
fn drop_flushes_every_login_channel() {
    let src = read_src("server.rs");
    assert!(
        src.contains("for entry in self.login_channels.iter()"),
        "Drop MUST iterate login_channels and flush each handle"
    );
    assert!(
        src.contains("self.login_channels.clear()"),
        "Drop MUST clear login_channels after the flush"
    );
}

/// Audit manifest at auth: `auth_succeeded` MUST fire
/// `IacsRecordingSessionStart` (via `IacsRecordingHub::
/// send_session_start`) with the SAME `connected_at_us` anchor as
/// every subsequent channel, so vauban-audit writes
/// `session.json` immediately and a zero-channel login still
/// leaves an on-disk artefact.
#[test]
fn auth_succeeded_sends_recording_session_start() {
    let src = read_src("server.rs");
    let auth_zone = src
        .split("async fn auth_succeeded")
        .nth(1)
        .and_then(|rest| rest.split("async fn channel_open_session").next())
        .expect("auth_succeeded body present");
    assert!(
        auth_zone.contains("hub.send_session_start("),
        "auth_succeeded MUST call IacsRecordingHub::send_session_start \
         so session.json is written at auth (zero-channel audit)"
    );
    assert!(
        auth_zone.contains("authenticated_at_us: anchor_us")
            && auth_zone.contains("connected_at_us: anchor_us"),
        "the SessionStart MUST reuse the connected_at_us anchor \
         captured at auth (directory-layout identity with the \
         channel PCAPs)"
    );
}

/// Drop-time audit finalization: `send_session_end` MUST be gated
/// on `ews_connected_emitted` (NOT `tunnel_active_emitted`) so a
/// zero-channel authenticated login still gets its `meta.json`
/// (`channels: []`) and its `session.json` close cause. The reason
/// comes from `SessionHandles::take_close_reason` (populated by the
/// terminate IPC) with the `ews_disconnect` fallback.
#[test]
fn drop_finalizes_recording_for_every_authenticated_login() {
    let src = read_src("server.rs");
    let drop_zone = src
        .split("impl Drop for IacsTunnelHandler")
        .nth(1)
        .expect("Drop impl present");
    assert!(
        drop_zone.contains("hub.send_session_end("),
        "Drop MUST call send_session_end so the audit bundle is \
         finalized"
    );
    assert!(
        !drop_zone.contains("self.tunnel_active_emitted.load(Ordering::SeqCst)\n                && let Some(ref hub) = self.recording"),
        "the send_session_end gate MUST NOT be tunnel_active_emitted \
         (that swallowed zero-channel sessions)"
    );
    assert!(
        drop_zone.contains("take_close_reason(&p.session_uuid)")
            && drop_zone.contains("\"ews_disconnect\".to_string()"),
        "Drop MUST attribute the close cause via \
         SessionHandles::take_close_reason with the ews_disconnect \
         fallback"
    );
}

/// The terminate IPC handler MUST record the close cause BEFORE
/// dispatching the russh disconnect, so the Handler `Drop` (which
/// russh fires asynchronously) attributes the
/// `IacsRecordingSessionEnd` to the terminate instead of a
/// voluntary `ews_disconnect`.
#[test]
fn terminate_ipc_records_close_reason_before_disconnect() {
    let src = read_src("main.rs");
    let terminate_zone = src
        .split("Message::IacsTunnelTerminate {")
        .nth(1)
        .expect("terminate arm present");
    let set_pos = terminate_zone
        .find("session_handles.set_close_reason(parsed, &reason)")
        .expect("terminate arm MUST call set_close_reason");
    let disconnect_pos = terminate_zone
        .find(".disconnect(")
        .expect("terminate arm dispatches Handle::disconnect");
    assert!(
        set_pos < disconnect_pos,
        "set_close_reason MUST run BEFORE the disconnect dispatch \
         (the Drop can fire as soon as russh processes the close)"
    );
}

/// The `WebReporter` type alias is the documented seam: tests can
/// disable IPC emission with `None`; production wires `Some(tx)`.
#[test]
fn web_reporter_type_alias_present() {
    let src = read_src("server.rs");
    assert!(
        src.contains("pub type WebReporter = Option<UnboundedSender<Message>>;"),
        "server.rs MUST expose the `WebReporter` type alias so \
         tests can opt out of IPC emission with `None`"
    );
}
