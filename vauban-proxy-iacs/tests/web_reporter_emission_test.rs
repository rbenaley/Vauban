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

#![allow(clippy::unwrap_used, clippy::panic)]

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
/// the active sessions surfaces. Only fires when a `tunnel_active`
/// was previously emitted -- a connection that never reached
/// `direct-tcpip` (failed auth, no channel) was never persisted as
/// `tunnel_active`, so there is nothing to close.
#[test]
fn handler_emits_iacs_tunnel_closed_on_drop() {
    let src = read_src("server.rs");
    assert!(
        src.contains("Message::IacsTunnelClosed {"),
        "server.rs MUST emit IacsTunnelClosed at handler-drop time"
    );
    assert!(
        src.contains("self.tunnel_active_emitted.load(Ordering::SeqCst)"),
        "server.rs MUST gate the IacsTunnelClosed emission on the \
         `tunnel_active_emitted` flag so a failed-auth connection \
         (which never persisted `tunnel_active`) does not generate a \
         spurious close event"
    );
    assert!(
        src.contains("reason: \"ews_disconnect\""),
        "server.rs MUST tag the drop-time IacsTunnelClosed reason \
         as `ews_disconnect` so operators can distinguish a clean \
         EWS shutdown from a server-initiated terminate"
    );
}

/// The relay tasks accumulate per-channel byte counts into the
/// per-EWS-login totals (`session_total_bytes_in/out`) so the
/// `IacsTunnelClosed` payload carries the cumulative traffic.
/// Drift here would either double-count (counters incremented twice)
/// or under-count (relay never flushes into the session totals).
#[test]
fn relay_accumulates_byte_counters_into_session_totals() {
    let src = read_src("server.rs");
    assert!(
        src.contains("session_total_bytes_in.fetch_add(")
            && src.contains("session_total_bytes_out.fetch_add("),
        "spawn_relay MUST push the per-channel byte counts into the \
         per-login totals so IacsTunnelClosed reports cumulative \
         traffic across every direct-tcpip channel of the EWS login"
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
