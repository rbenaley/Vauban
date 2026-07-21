//! IPC client for communication with vauban-proxy-iacs.
//!
//! `vauban-proxy-iacs` owns the in-process russh sshd that EWS clients
//! `ssh -L`-tunnel into. vauban-web is the **control plane** for that
//! proxy: it mints a `SessionToken` via `vauban-access`, INSERTs the
//! `proxy_sessions` row, and then asks proxy-iacs to materialize a
//! pending tunnel. The actual byte relay never touches vauban-web.
//!
//! The wire surface is intentionally small: a single open verb
//! (`IacsTunnelOpen` -> `IacsTunnelOpened`), a terminate verb
//! (`IacsTunnelTerminate`) used by the revocation watchdog, a boot
//! resync verb (`IacsTunnelSnapshotRequest` ->
//! `IacsTunnelSnapshotResponse`) so vauban-web can rehydrate DB rows
//! from the proxy as source of truth after a web-only restart, and a
//! status-update notification (`IacsTunnelStatusUpdate` /
//! `IacsTunnelClosed`) that proxy-iacs pushes on its own when the
//! lifecycle changes. See [`shared/src/messages.rs`] for the full
//! definitions, and the per-asset target plan in
//! `.cursor/plans/iacs_proxy_per-asset_target_efa20838.plan.md`.

use crate::db::DbPool;
use crate::error::{AppError, AppResult};
use crate::models::session::SessionStatus;
use crate::services::broadcast::{BroadcastService, WsChannel};
use serde_json::json;
use shared::ipc::IpcChannel;
use shared::messages::{IacsTunnelSnapshotEntry, Message};
use std::collections::HashMap;
use std::io;
use std::os::unix::io::RawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::sync::{Mutex, oneshot};
use tracing::{debug, error, info, warn};

/// Request to open an IACS tunnel pending session.
///
/// All fields are de-correlated from the DB so proxy-iacs can stay
/// DB-less: the EWS pinning and the access-rule decision were both
/// performed by vauban-web before this request is sent.
#[derive(Clone, Debug)]
pub struct IacsTunnelOpenRequest {
    /// `proxy_sessions.uuid` (string form). Used by proxy-iacs as the
    /// SSH `username` field a EWS client must present.
    pub session_id: String,
    pub user_uuid: String,
    pub asset_uuid: String,
    /// EWS row UUID pinned by vauban-web at session creation. Re-sent
    /// for forensic logging only; proxy-iacs trusts the
    /// `ews_pubkey_fp` field for the `auth_publickey` decision.
    pub ews_uuid: String,
    /// SHA-256 hex of the EWS public key in `russh::keys::ssh-key`
    /// canonical SSH wire form. proxy-iacs compares this against
    /// `fingerprint(offered_key)` during `auth_publickey`.
    pub ews_pubkey_fp: String,
    /// Per-asset hostname (FQDN or IP). Replaces the legacy MVP
    /// fixed loopback target.
    pub asset_host: String,
    pub asset_port: u16,
    /// Industrial protocol label (`"modbus"`, `"opcua"`, `"tcp"`,
    /// ...). Forwarded to proxy-iacs for the per-channel wire-protocol
    /// gate (`ExpectedProfile` / `classify_peek`) and retained for
    /// forensic Inspect Capture / session metadata.
    pub industrial_protocol: String,
    /// Pending-session deadline (seconds from now). Mirrors
    /// `[industrial.iacs_tunnel].waiting_client_ttl_seconds` so the
    /// proxy can garbage-collect a pending entry that no EWS ever
    /// claimed.
    pub ttl_seconds: u32,
    /// Cryptographic session token (BLAKE3-keyed MAC) issued by
    /// vauban-access, bound to
    /// `(user_uuid, asset_uuid, "iacs_tunnel", host, port,
    ///  Service::ProxyIacs, session_id)`. proxy-iacs verifies via
    /// `Verifier::Proxy` BEFORE caching the pending entry.
    pub session_token: Vec<u8>,
}

/// Response from opening an IACS tunnel pending session.
#[derive(Debug, Clone)]
pub struct IacsTunnelOpened {
    pub request_id: u64,
    pub session_id: String,
    pub success: bool,
    pub error: Option<String>,
}

/// Async client for communicating with vauban-proxy-iacs.
pub struct ProxyIacsClient {
    channel: IpcChannel,
    read_async_fd: AsyncFd<RawFd>,
    next_request_id: AtomicU64,
    pending_open_requests: Mutex<HashMap<u64, oneshot::Sender<IacsTunnelOpened>>>,
    pending_snapshot_requests: Mutex<HashMap<u64, oneshot::Sender<Vec<IacsTunnelSnapshotEntry>>>>,
    /// Optional broadcast handle, set by
    /// [`ProxyIacsClient::process_incoming_with_state`] before
    /// the loop starts. When present, every incoming
    /// `IacsTunnelStatusUpdate` / `IacsTunnelClosed` is fanned out
    /// on `WsChannel::SessionLive(<session_id>)` so the status page
    /// flips between `waiting_client` -> `tunnel_active` ->
    /// `tunnel_closed` in real time without DB polling, AND on the
    /// admin-wide `WsChannel::ActiveSessionsList` (rendered from the
    /// freshly-persisted DB state) so the `/sessions/active` page
    /// gains/loses the IACS row in real time alongside SSH/RDP.
    broadcast: Mutex<Option<BroadcastService>>,
    /// Optional DB pool, set by [`ProxyIacsClient::process_incoming_with_state`]
    /// before the loop starts. When present, every
    /// `IacsTunnelStatusUpdate { status = "tunnel_active", peer_ip }`
    /// flips `proxy_sessions.status = "tunnel_active"`,
    /// `connected_at = NOW()`, `client_ip = peer_ip` in the DB so the
    /// admin `/sessions/active` page can surface the tunnel by the
    /// same SQL filter it uses for SSH/RDP. Symmetrically,
    /// `IacsTunnelClosed` flips status to `terminated` /
    /// `disconnected_at = NOW()` so the row leaves the active list.
    /// Without this seam (`broadcast`-only flavour, the pre-issue
    /// integration), the IACS lifecycle was visible only on the
    /// per-session viewer, never on the admin dashboard.
    db_pool: Mutex<Option<DbPool>>,
    app_state: Mutex<Option<crate::AppState>>,
}

impl ProxyIacsClient {
    /// Create a new IACS proxy client.
    ///
    /// File descriptors are passed by the supervisor.
    pub fn new(read_fd: RawFd, write_fd: RawFd) -> io::Result<Arc<Self>> {
        let channel = unsafe { IpcChannel::from_raw_fds(read_fd, write_fd) };

        set_nonblocking(read_fd)?;

        let read_async_fd = AsyncFd::new(read_fd)?;

        Ok(Arc::new(Self {
            channel,
            read_async_fd,
            next_request_id: AtomicU64::new(1),
            pending_open_requests: Mutex::new(HashMap::new()),
            pending_snapshot_requests: Mutex::new(HashMap::new()),
            broadcast: Mutex::new(None),
            db_pool: Mutex::new(None),
            app_state: Mutex::new(None),
        }))
    }

    /// Like [`Self::process_incoming`] but stashes a broadcast
    /// handle and a DB pool first so `IacsTunnelStatusUpdate` /
    /// `IacsTunnelClosed` notifications can:
    /// - flip `proxy_sessions.status` / `connected_at` /
    ///   `disconnected_at` / `client_ip` in the DB so the admin
    ///   `/sessions/active` page picks the tunnel up by its SQL
    ///   filter (the same one SSH/RDP rely on);
    /// - fan out a fresh active-list HTML fragment so subscribers
    ///   to `WsChannel::ActiveSessionsList` see the row appear /
    ///   disappear in real time;
    /// - fan out the per-session JSON payload on
    ///   `WsChannel::SessionLive(<session_id>)` for the tunnel
    ///   status page (unchanged).
    ///
    /// SECURITY: this is the **only** place where the IACS lifecycle
    /// transitions are persisted. No HTTP handler may set
    /// `proxy_sessions.status = "tunnel_active"` (only the proxy can
    /// observe the EWS handshake), nor may any HTTP handler short-
    /// circuit the closure path: `IacsTunnelClosed` from the proxy is
    /// the canonical signal that the EWS is gone.
    pub async fn process_incoming_with_state(
        self: Arc<Self>,
        broadcast: BroadcastService,
        db_pool: DbPool,
        app_state: crate::AppState,
    ) -> AppResult<()> {
        {
            let mut slot = self.broadcast.lock().await;
            *slot = Some(broadcast);
        }
        {
            let mut slot = self.db_pool.lock().await;
            *slot = Some(db_pool);
        }
        {
            let mut slot = self.app_state.lock().await;
            *slot = Some(app_state);
        }
        self.process_incoming().await
    }

    /// Backwards-compatible shim: keep the broadcast-only entry-point
    /// for tests that don't need the DB persistence side-effect (and
    /// for any future caller that wants the per-session WS fan-out
    /// without the admin-list integration).
    #[cfg(test)]
    pub async fn process_incoming_with_broadcast(
        self: Arc<Self>,
        broadcast: BroadcastService,
    ) -> AppResult<()> {
        {
            let mut slot = self.broadcast.lock().await;
            *slot = Some(broadcast);
        }
        self.process_incoming().await
    }

    /// Materialize a pending IACS tunnel on proxy-iacs.
    ///
    /// Sends an `IacsTunnelOpen` IPC, waits for `IacsTunnelOpened`,
    /// times out after 30 s.
    pub async fn open_tunnel(&self, request: IacsTunnelOpenRequest) -> AppResult<IacsTunnelOpened> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::SeqCst);
        let session_id = request.session_id.clone();

        debug!(
            request_id = request_id,
            session_id = %session_id,
            asset_host = %request.asset_host,
            asset_port = request.asset_port,
            "Opening IACS tunnel pending session"
        );

        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.pending_open_requests.lock().await;
            pending.insert(request_id, tx);
        }

        let msg = Message::IacsTunnelOpen {
            request_id,
            session_id,
            user_uuid: request.user_uuid,
            asset_uuid: request.asset_uuid,
            ews_uuid: request.ews_uuid,
            ews_pubkey_fp: request.ews_pubkey_fp,
            asset_host: request.asset_host,
            asset_port: request.asset_port,
            industrial_protocol: request.industrial_protocol,
            ttl_seconds: request.ttl_seconds,
            session_token: request.session_token,
        };

        self.channel
            .send(&msg)
            .map_err(|e| AppError::Ipc(format!("IPC send failed: {}", e)))?;

        match tokio::time::timeout(std::time::Duration::from_secs(30), rx).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => Err(AppError::Ipc("Response channel dropped".to_string())),
            Err(_) => {
                let mut pending = self.pending_open_requests.lock().await;
                pending.remove(&request_id);
                Err(AppError::Ipc("IACS tunnel open timeout".to_string()))
            }
        }
    }

    /// Force-terminate a live IACS tunnel from the revocation watchdog.
    ///
    /// Fire-and-forget: the watchdog flips DB state independently and
    /// proxy-iacs will emit a `IacsTunnelClosed` notification when the
    /// session loop ends.
    pub fn terminate_tunnel(&self, session_id: &str, reason: &str) -> AppResult<()> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::SeqCst);
        let msg = Message::IacsTunnelTerminate {
            request_id,
            session_id: session_id.to_string(),
            reason: reason.to_string(),
        };
        self.channel
            .send(&msg)
            .map_err(|e| AppError::Ipc(format!("IPC send failed: {}", e)))
    }

    /// Ask proxy-iacs for all live IACS tunnel state (boot resync).
    ///
    /// Requires [`Self::process_incoming`] (or
    /// [`Self::process_incoming_with_state`]) to be running so the
    /// `IacsTunnelSnapshotResponse` can be delivered. Times out after
    /// 10 s; callers treat timeout/error as fail-closed (empty
    /// snapshot => terminate every live DB row).
    pub async fn snapshot_tunnels(&self) -> AppResult<Vec<IacsTunnelSnapshotEntry>> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::SeqCst);
        debug!(request_id, "Requesting IACS tunnel snapshot from proxy");

        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.pending_snapshot_requests.lock().await;
            pending.insert(request_id, tx);
        }

        let msg = Message::IacsTunnelSnapshotRequest { request_id };
        if let Err(e) = self.channel.send(&msg) {
            let mut pending = self.pending_snapshot_requests.lock().await;
            pending.remove(&request_id);
            return Err(AppError::Ipc(format!("IPC send failed: {}", e)));
        }

        match tokio::time::timeout(std::time::Duration::from_secs(10), rx).await {
            Ok(Ok(entries)) => Ok(entries),
            Ok(Err(_)) => Err(AppError::Ipc(
                "IACS snapshot response channel dropped".to_string(),
            )),
            Err(_) => {
                let mut pending = self.pending_snapshot_requests.lock().await;
                pending.remove(&request_id);
                Err(AppError::Ipc("IACS tunnel snapshot timeout".to_string()))
            }
        }
    }

    /// Drain incoming messages from the proxy.
    ///
    /// Run forever in a dedicated task. Closes the loop on a
    /// `ConnectionClosed` IPC error (proxy-iacs respawn).
    ///
    /// Uses [`AsyncFdReadyGuard::try_io`] so the WouldBlock /
    /// `clear_ready` race cannot strand a response in the pipe
    /// (classic edge-triggered lost-wakeup). Without that, dense
    /// E2E connect-iacs suites flake on `open_tunnel` 30 s timeouts.
    pub async fn process_incoming(&self) -> AppResult<()> {
        loop {
            let mut guard = self
                .read_async_fd
                .ready(Interest::READABLE)
                .await
                .map_err(|e| AppError::Ipc(format!("AsyncFd ready failed: {}", e)))?;

            loop {
                let try_result = guard.try_io(|_| match self.channel.try_recv() {
                    Ok(msg) => Ok(msg),
                    Err(shared::ipc::IpcError::Io(ref e))
                        if e.kind() == io::ErrorKind::WouldBlock =>
                    {
                        Err(io::Error::new(io::ErrorKind::WouldBlock, "would block"))
                    }
                    Err(shared::ipc::IpcError::ConnectionClosed) => Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "IPC connection closed",
                    )),
                    Err(e) => Err(io::Error::other(e.to_string())),
                });

                match try_result {
                    Ok(Ok(msg)) => {
                        self.handle_message(msg).await;
                    }
                    Ok(Err(e)) if e.kind() == io::ErrorKind::ConnectionReset => {
                        info!("IACS proxy IPC connection closed");
                        return Err(AppError::Ipc("IPC connection closed".to_string()));
                    }
                    Ok(Err(e)) => {
                        error!(error = %e, "IPC receive error");
                        break;
                    }
                    // `try_io` already cleared readiness on WouldBlock.
                    Err(_would_block) => break,
                }
            }
        }
    }

    /// Blocking IPC drain for integration-test mocks.
    ///
    /// Preferable to [`Self::process_incoming`] when the pump runs on
    /// a dedicated OS thread: `recv` uses `poll(2)` and never depends
    /// on the Tokio `AsyncFd` edge-trigger path. Each message is
    /// handled via `rt.block_on` on the caller's current-thread
    /// runtime (must be invoked from that runtime's owning thread,
    /// outside any nested `block_on`).
    pub fn process_incoming_blocking_on(&self, rt: &tokio::runtime::Runtime) -> AppResult<()> {
        loop {
            match self.channel.recv() {
                Ok(msg) => {
                    rt.block_on(self.handle_message(msg));
                }
                Err(shared::ipc::IpcError::ConnectionClosed) => {
                    info!("IACS proxy IPC connection closed");
                    return Err(AppError::Ipc("IPC connection closed".to_string()));
                }
                Err(e) => {
                    error!(error = %e, "IPC receive error");
                    return Err(AppError::Ipc(format!("IPC receive error: {e}")));
                }
            }
        }
    }

    async fn handle_message(&self, msg: Message) {
        match msg {
            Message::IacsTunnelOpened {
                request_id,
                session_id,
                success,
                error,
            } => {
                debug!(
                    request_id = request_id,
                    session_id = %session_id,
                    success = success,
                    "IACS tunnel opened response"
                );

                let response = IacsTunnelOpened {
                    request_id,
                    session_id,
                    success,
                    error,
                };

                let mut pending = self.pending_open_requests.lock().await;
                if let Some(tx) = pending.remove(&request_id) {
                    let _ = tx.send(response);
                }
            }

            Message::IacsTunnelSnapshotResponse {
                request_id,
                entries,
            } => {
                debug!(
                    request_id = request_id,
                    entries = entries.len(),
                    "IACS tunnel snapshot response"
                );
                let mut pending = self.pending_snapshot_requests.lock().await;
                if let Some(tx) = pending.remove(&request_id) {
                    let _ = tx.send(entries);
                }
            }

            // Status updates from proxy-iacs (Lot 5). Fanned out on
            // the per-session `WsChannel::SessionLive(<session_id>)`
            // so the status page flips status pills + byte counters
            // without DB polling. The channel is parametric (one
            // instance per session) so the broadcast level is
            // `debug!` per `websocket-logging.mdc`.
            //
            // When `status == "tunnel_active"` AND a DB pool was
            // wired via `process_incoming_with_state`, we also flip
            // `proxy_sessions.status = "tunnel_active"`,
            // `connected_at = NOW()`, and (if `peer_ip` is known)
            // `client_ip = peer_ip`. This is the seam that lets the
            // admin `/sessions/active` page surface IACS tunnels
            // alongside SSH/RDP through the same SQL filter
            // (`status IN ('active', 'tunnel_active')`).
            Message::IacsTunnelStatusUpdate {
                session_id,
                status,
                bytes_in,
                bytes_out,
                peer_ip,
            } => {
                debug!(
                    session_id = %session_id,
                    status = %status,
                    bytes_in = bytes_in,
                    bytes_out = bytes_out,
                    "IACS tunnel status update received"
                );
                let mut db_persisted = false;
                if status == "ews_connected"
                    && let Some(pool) = self.db_pool.lock().await.as_ref()
                {
                    // The EWS SSH handshake succeeded: anchor
                    // `connected_at` / `client_ip` and surface the
                    // row on /sessions/active even before the first
                    // direct-tcpip channel. When IACS recording is
                    // on, `is_recorded` / `recording_path` are set
                    // HERE (not at close) so a zero-channel session
                    // already points at its audit manifest.
                    let app_state = self.app_state.lock().await.clone();
                    let iacs_recording = app_state
                        .as_ref()
                        .map(|s| s.config.recording.iacs_recording_enabled())
                        .unwrap_or(false);
                    let storage_path = app_state
                        .as_ref()
                        .map(|s| s.config.recording.storage_path.as_str())
                        .unwrap_or("");
                    match persist_ews_connected(
                        pool,
                        &session_id,
                        peer_ip.as_deref(),
                        iacs_recording,
                        storage_path,
                    )
                    .await
                    {
                        Ok(updated) => {
                            if updated {
                                debug!(
                                    session_id = %session_id,
                                    "iacs_tunnel: proxy_sessions row \
                                     flipped to ews_connected"
                                );
                                db_persisted = true;
                            } else {
                                debug!(
                                    session_id = %session_id,
                                    "iacs_tunnel: no waiting_client \
                                     row to flip to ews_connected \
                                     (already active or terminated)"
                                );
                            }
                        }
                        Err(e) => {
                            error!(
                                session_id = %session_id,
                                error = %e,
                                "iacs_tunnel: failed to flip status \
                                 to ews_connected in DB"
                            );
                        }
                    }
                }
                if status == "tunnel_active"
                    && let Some(pool) = self.db_pool.lock().await.as_ref()
                {
                    match persist_tunnel_active(pool, &session_id, peer_ip.as_deref()).await {
                        Ok(updated) => {
                            if updated {
                                debug!(
                                    session_id = %session_id,
                                    "iacs_tunnel: proxy_sessions row \
                                     flipped to tunnel_active"
                                );
                                db_persisted = true;
                            } else {
                                // No row matched -- either the
                                // session was already torn down or
                                // never existed. Idempotent: log at
                                // debug, do not fail the IPC loop.
                                debug!(
                                    session_id = %session_id,
                                    "iacs_tunnel: no waiting_client \
                                     or ews_connected row to flip \
                                     (already active or terminated)"
                                );
                            }
                        }
                        Err(e) => {
                            error!(
                                session_id = %session_id,
                                error = %e,
                                "iacs_tunnel: failed to flip status \
                                 to tunnel_active in DB"
                            );
                        }
                    }
                }
                // Wire vocabulary: canonical SessionLive types from
                // `services::iacs_tunnel::ws_vocab` so the Alpine
                // `iacsTunnelStatus` component reacts. The pre-fix
                // envelope (a distinct iacs_tunnel_* type plus a
                // nested status field) was invisible to the
                // component: the status page countdown kept ticking
                // over an active tunnel. Pinned by
                // `tests/web/iacs_ws_vocab_test.rs`.
                let event_type =
                    crate::services::iacs_tunnel::ws_vocab::event_type_for_status(&status);
                let payload = json!({
                    "type": event_type,
                    "session_id": session_id,
                    "bytes_in": bytes_in,
                    "bytes_out": bytes_out,
                    "peer_ip": peer_ip,
                });
                let channel_name = WsChannel::SessionLive(session_id.clone()).as_str();
                let broadcast_handle = self.broadcast.lock().await.clone();
                if let Some(b) = broadcast_handle.as_ref() {
                    let _ = b.send_raw(&channel_name, payload.to_string()).await;
                }
                // Active-list fan-out only fires when a row actually
                // changed: a `tunnel_stats` ping arriving every few
                // seconds would otherwise re-render the whole admin
                // list for nothing.
                if db_persisted {
                    let pool_handle = self.db_pool.lock().await.clone();
                    if let (Some(b), Some(pool)) = (broadcast_handle.as_ref(), pool_handle.as_ref())
                    {
                        // This pusher only runs while processing an IACS
                        // IPC message, which only happens when the IACS
                        // proxy is connected -- i.e. industrial.enabled =
                        // true. Pass `true` so the IACS row it just
                        // persisted is surfaced (not filtered out).
                        crate::tasks::dashboard::push_active_sessions_update(b, pool, true).await;
                    }
                }
            }

            Message::IacsTunnelClosed {
                session_id,
                reason,
                bytes_in,
                bytes_out,
                peer_ip,
                ..
            } => {
                debug!(
                    session_id = %session_id,
                    reason = %reason,
                    bytes_in = bytes_in,
                    bytes_out = bytes_out,
                    "IACS tunnel closed"
                );
                let mut db_persisted = false;
                let app_state = self.app_state.lock().await.clone();
                let iacs_recording = app_state
                    .as_ref()
                    .map(|s| s.config.recording.iacs_recording_enabled())
                    .unwrap_or(false);
                let storage_path = app_state
                    .as_ref()
                    .map(|s| s.config.recording.storage_path.as_str())
                    .unwrap_or("");
                if let Some(pool) = self.db_pool.lock().await.as_ref() {
                    match persist_tunnel_closed(pool, &session_id, iacs_recording, storage_path)
                        .await
                    {
                        Ok(updated) => {
                            if updated {
                                debug!(
                                    session_id = %session_id,
                                    "iacs_tunnel: proxy_sessions row \
                                     flipped to terminated"
                                );
                                db_persisted = true;
                                if iacs_recording
                                    && let (Some(state), Ok(session_uuid)) =
                                        (app_state.as_ref(), uuid::Uuid::parse_str(&session_id))
                                {
                                    std::mem::drop(
                                        crate::services::recording_hydrator::enqueue_hydration_by_uuid(
                                            state,
                                            session_uuid,
                                            std::time::Duration::from_secs(
                                                state.config.recording.hydration_enqueue_delay_secs,
                                            ),
                                        ),
                                    );
                                }
                            } else {
                                debug!(
                                    session_id = %session_id,
                                    "iacs_tunnel: no live row to mark \
                                     terminated (already gone)"
                                );
                            }
                        }
                        Err(e) => {
                            error!(
                                session_id = %session_id,
                                error = %e,
                                "iacs_tunnel: failed to flip status \
                                 to terminated in DB"
                            );
                        }
                    }
                }
                // Canonical close event -- see the vocabulary note on
                // the `IacsTunnelStatusUpdate` arm above.
                let payload = json!({
                    "type": crate::services::iacs_tunnel::ws_vocab::TYPE_TUNNEL_CLOSED,
                    "session_id": session_id,
                    "reason": reason,
                    "bytes_in": bytes_in,
                    "bytes_out": bytes_out,
                    "peer_ip": peer_ip,
                });
                let channel_name = WsChannel::SessionLive(session_id.clone()).as_str();
                let broadcast_handle = self.broadcast.lock().await.clone();
                if let Some(b) = broadcast_handle.as_ref() {
                    let _ = b.send_raw(&channel_name, payload.to_string()).await;
                }
                if db_persisted {
                    let pool_handle = self.db_pool.lock().await.clone();
                    if let (Some(b), Some(pool)) = (broadcast_handle.as_ref(), pool_handle.as_ref())
                    {
                        // This pusher only runs while processing an IACS
                        // IPC message, which only happens when the IACS
                        // proxy is connected -- i.e. industrial.enabled =
                        // true. Pass `true` so the IACS row it just
                        // persisted is surfaced (not filtered out).
                        crate::tasks::dashboard::push_active_sessions_update(b, pool, true).await;
                    }
                }
            }

            Message::IacsProxyHealth {
                ack_timeouts,
                ack_dropped,
                ack_wait_ms_max,
            } => {
                let app_state = self.app_state.lock().await.clone();
                if let Some(state) = app_state.as_ref() {
                    let tel = &state.iacs_recording_telemetry;
                    let prev_timeouts = tel.ack_timeouts.load(Ordering::SeqCst);
                    tel.ack_timeouts.store(ack_timeouts, Ordering::SeqCst);
                    tel.ack_dropped.store(ack_dropped, Ordering::SeqCst);
                    tel.ack_wait_ms_max.store(ack_wait_ms_max, Ordering::SeqCst);

                    if ack_timeouts > prev_timeouts {
                        let should_notify = tel
                            .ack_timeouts_notified_at
                            .lock()
                            .ok()
                            .map(|mut last| {
                                let notify = last
                                    .map(|t| t.elapsed() >= Duration::from_secs(60))
                                    .unwrap_or(true);
                                if notify {
                                    *last = Some(Instant::now());
                                }
                                notify
                            })
                            .unwrap_or(false);
                        if should_notify {
                            let payload = json!({
                                "type": "iacs_recording_ack_timeout",
                                "ack_timeouts": ack_timeouts,
                                "ack_wait_ms_max": ack_wait_ms_max,
                            });
                            if let Some(b) = self.broadcast.lock().await.as_ref() {
                                let _ = b
                                    .send_raw(
                                        &WsChannel::Notifications.as_str(),
                                        payload.to_string(),
                                    )
                                    .await;
                            }
                        }
                    }
                }
            }

            _ => {
                warn!(?msg, "Ignoring unexpected message from proxy-iacs");
            }
        }
    }
}

/// Flip a `proxy_sessions` row from `waiting_client` to
/// `ews_connected`, anchor `connected_at` at the current wall clock,
/// and (if `peer_ip` is provided and parses as a valid IP) update
/// `client_ip` so the admin `/sessions/active` page shows the EWS's
/// actual source instead of the WebUI browser IP captured at
/// session creation time.
///
/// When `iacs_recording` is on, `is_recorded` / `recording_path`
/// are set in the SAME statement (anchored on the fresh
/// `connected_at`): a zero-channel authenticated session must
/// already point at its audit manifest directory.
///
/// Returns `Ok(true)` if a row was updated, `Ok(false)` if no row
/// matched (idempotent). Gated on `status = 'waiting_client'` so a
/// re-delivery cannot reset `connected_at`, and an out-of-order
/// arrival AFTER `tunnel_active` cannot demote the row.
///
/// Exposed publicly (with `#[doc(hidden)]`) for the integration
/// suite -- see [`persist_tunnel_active`].
#[doc(hidden)]
pub async fn persist_ews_connected(
    pool: &DbPool,
    session_id: &str,
    peer_ip: Option<&str>,
    iacs_recording: bool,
    storage_path: &str,
) -> AppResult<bool> {
    use crate::schema::proxy_sessions::dsl as ps;
    use diesel::ExpressionMethods;
    use diesel_async::RunQueryDsl;

    let session_uuid = uuid::Uuid::parse_str(session_id)
        .map_err(|e| AppError::Validation(format!("invalid session UUID: {}", e)))?;

    let mut conn = pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB pool: {}", e)))?;

    let now = chrono::Utc::now();
    let parsed_peer_ip = peer_ip.and_then(|s| s.parse::<std::net::IpAddr>().ok());
    let recording_path = iacs_recording.then(|| {
        crate::services::recording_hydrator::recording_dir_for_session(
            storage_path,
            session_id,
            now,
        )
    });

    // Four flavours of the UPDATE so we never write a `client_ip`
    // value that did not come from the proxy, nor recording flags
    // when recording is off (same rationale as
    // `persist_tunnel_active`).
    let base = diesel::update(ps::proxy_sessions)
        .filter(ps::uuid.eq(session_uuid))
        .filter(ps::status.eq("waiting_client"));
    let updated = match (parsed_peer_ip, recording_path) {
        (Some(ip), Some(path)) => {
            base.set((
                ps::status.eq("ews_connected"),
                ps::connected_at.eq(now),
                ps::client_ip.eq(ipnetwork::IpNetwork::from(ip)),
                ps::is_recorded.eq(true),
                ps::recording_path.eq(path),
            ))
            .execute(&mut conn)
            .await
        }
        (Some(ip), None) => {
            base.set((
                ps::status.eq("ews_connected"),
                ps::connected_at.eq(now),
                ps::client_ip.eq(ipnetwork::IpNetwork::from(ip)),
            ))
            .execute(&mut conn)
            .await
        }
        (None, Some(path)) => {
            base.set((
                ps::status.eq("ews_connected"),
                ps::connected_at.eq(now),
                ps::is_recorded.eq(true),
                ps::recording_path.eq(path),
            ))
            .execute(&mut conn)
            .await
        }
        (None, None) => {
            base.set((ps::status.eq("ews_connected"), ps::connected_at.eq(now)))
                .execute(&mut conn)
                .await
        }
    }
    .map_err(AppError::Database)?;
    Ok(updated > 0)
}

/// Flip a `proxy_sessions` row from `waiting_client` or
/// `ews_connected` to `tunnel_active`. `connected_at` is anchored
/// via `COALESCE`: the `ews_connected` transition normally set it at
/// SSH-auth time and the first `direct-tcpip` must NOT move it (the
/// recording directory layout is derived from it); the legacy
/// in-process path that jumps straight from `waiting_client` still
/// gets a fresh anchor. If `peer_ip` is provided and parses as a
/// valid IP, `client_ip` is updated so the admin `/sessions/active`
/// page shows the EWS's actual source instead of the WebUI browser
/// IP captured at session creation time.
///
/// Returns `Ok(true)` if a row was updated, `Ok(false)` if no row
/// matched (idempotent, e.g. the session was terminated before the
/// proxy reported the active status). The status gate makes a
/// re-delivery of the same IPC message a no-op.
///
/// Exposed publicly (with `#[doc(hidden)]`) so the integration
/// suite at `tests/ipc/iacs_lifecycle_persistence_test.rs` can pin
/// the behaviour without spawning a full proxy-iacs subprocess.
/// Not part of the public API; production code MUST call this
/// indirectly via [`ProxyIacsClient::process_incoming_with_state`].
#[doc(hidden)]
pub async fn persist_tunnel_active(
    pool: &DbPool,
    session_id: &str,
    peer_ip: Option<&str>,
) -> AppResult<bool> {
    use crate::schema::proxy_sessions::dsl as ps;
    use diesel::ExpressionMethods;
    use diesel_async::RunQueryDsl;

    let session_uuid = uuid::Uuid::parse_str(session_id)
        .map_err(|e| AppError::Validation(format!("invalid session UUID: {}", e)))?;

    let mut conn = pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB pool: {}", e)))?;

    let parsed_peer_ip = peer_ip.and_then(|s| s.parse::<std::net::IpAddr>().ok());

    // `COALESCE(connected_at, NOW())`: keep the ews_connected-time
    // anchor when present, seed one otherwise (legacy in-process
    // sshd emits tunnel_active without a prior ews_connected).
    fn keep_or_now()
    -> diesel::expression::SqlLiteral<diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>>
    {
        diesel::dsl::sql("COALESCE(connected_at, NOW())")
    }

    // Two flavours of the UPDATE so we never write a `client_ip`
    // value that did not come from the proxy. Diesel's typed
    // builder otherwise forces us to materialise a default
    // `IpNetwork`, which would silently overwrite the WebUI IP
    // even when proxy-iacs did not report a peer.
    let updated = if let Some(ip) = parsed_peer_ip {
        let net = ipnetwork::IpNetwork::from(ip);
        diesel::update(ps::proxy_sessions)
            .filter(ps::uuid.eq(session_uuid))
            .filter(ps::status.eq_any(SessionStatus::WAITING_TTL_AS_STR))
            .set((
                ps::status.eq("tunnel_active"),
                ps::connected_at.eq(keep_or_now()),
                ps::client_ip.eq(net),
            ))
            .execute(&mut conn)
            .await
            .map_err(AppError::Database)?
    } else {
        diesel::update(ps::proxy_sessions)
            .filter(ps::uuid.eq(session_uuid))
            .filter(ps::status.eq_any(SessionStatus::WAITING_TTL_AS_STR))
            .set((
                ps::status.eq("tunnel_active"),
                ps::connected_at.eq(keep_or_now()),
            ))
            .execute(&mut conn)
            .await
            .map_err(AppError::Database)?
    };
    Ok(updated > 0)
}

/// Flip a `proxy_sessions` row from a live IACS state
/// (`waiting_client`, `ews_connected` or `tunnel_active`) to
/// `terminated` and anchor `disconnected_at`. Idempotent: subsequent
/// calls for the same session find no matching row and return
/// `Ok(false)` without touching the timestamp.
///
/// Counter-balances the optimistic `tunnel_active` filter from
/// [`persist_tunnel_active`]: if proxy-iacs misses the
/// `waiting_client -> tunnel_active` transition (e.g. the EWS
/// disconnects before the first relay byte), `IacsTunnelClosed` is
/// still authoritative and clears the row from the active list.
///
/// Exposed publicly (with `#[doc(hidden)]`) for the integration
/// suite -- see [`persist_tunnel_active`].
#[doc(hidden)]
pub async fn persist_tunnel_closed(
    pool: &DbPool,
    session_id: &str,
    iacs_recording: bool,
    storage_path: &str,
) -> AppResult<bool> {
    use crate::schema::proxy_sessions::dsl as ps;
    use diesel::ExpressionMethods;
    use diesel::OptionalExtension;
    use diesel::QueryDsl;
    use diesel_async::RunQueryDsl;

    let session_uuid = uuid::Uuid::parse_str(session_id)
        .map_err(|e| AppError::Validation(format!("invalid session UUID: {}", e)))?;

    let mut conn = pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB pool: {}", e)))?;

    let now = chrono::Utc::now();
    let connected_at: Option<chrono::DateTime<chrono::Utc>> = ps::proxy_sessions
        .filter(ps::uuid.eq(session_uuid))
        .select(ps::connected_at)
        .first::<Option<chrono::DateTime<chrono::Utc>>>(&mut conn)
        .await
        .optional()
        .map_err(AppError::Database)?
        .flatten();

    let path_anchor = connected_at.unwrap_or(now);
    let updated = if iacs_recording {
        let recording_path = crate::services::recording_hydrator::recording_dir_for_session(
            storage_path,
            session_id,
            path_anchor,
        );
        diesel::update(ps::proxy_sessions)
            .filter(ps::uuid.eq(session_uuid))
            .filter(ps::status.eq_any(SessionStatus::IACS_OPEN_AS_STR))
            .set((
                ps::status.eq("terminated"),
                ps::disconnected_at.eq(now),
                ps::is_recorded.eq(true),
                ps::recording_path.eq(recording_path),
            ))
            .execute(&mut conn)
            .await
            .map_err(AppError::Database)?
    } else {
        diesel::update(ps::proxy_sessions)
            .filter(ps::uuid.eq(session_uuid))
            .filter(ps::status.eq_any(SessionStatus::IACS_OPEN_AS_STR))
            .set((ps::status.eq("terminated"), ps::disconnected_at.eq(now)))
            .execute(&mut conn)
            .await
            .map_err(AppError::Database)?
    };
    Ok(updated > 0)
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    use libc::{F_GETFL, F_SETFL, O_NONBLOCK, fcntl};

    unsafe {
        let flags = fcntl(fd, F_GETFL);
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_request(session_id: &str, host: &str, port: u16) -> IacsTunnelOpenRequest {
        IacsTunnelOpenRequest {
            session_id: session_id.to_string(),
            user_uuid: "u".to_string(),
            asset_uuid: "a".to_string(),
            ews_uuid: "e".to_string(),
            ews_pubkey_fp: "deadbeef".to_string(),
            asset_host: host.to_string(),
            asset_port: port,
            industrial_protocol: "tcp".to_string(),
            ttl_seconds: 300,
            session_token: vec![1, 2, 3, 4],
        }
    }

    #[test]
    fn test_request_clone() {
        let r = make_request("s", "h", 4321);
        let c = r.clone();
        assert_eq!(c.session_id, r.session_id);
        assert_eq!(c.asset_host, r.asset_host);
        assert_eq!(c.asset_port, r.asset_port);
        assert_eq!(c.session_token, r.session_token);
    }

    #[test]
    fn test_iacs_tunnel_opened_clone() {
        let r = IacsTunnelOpened {
            request_id: 7,
            session_id: "s".to_string(),
            success: true,
            error: None,
        };
        let c = r.clone();
        assert_eq!(c.request_id, 7);
        assert!(c.success);
    }

    /// SECURITY: the legacy MVP fixed loopback target literal must
    /// NOT appear in this IPC client. The legacy MVP fixed target
    /// was the bug we are fixing in this lot; per-asset `host:port`
    /// is now passed from vauban-web through
    /// `IacsTunnelOpenRequest::asset_host` / `asset_port`.
    ///
    /// The forbidden bytes are reconstructed at runtime so they
    /// never appear literally in this file (and therefore cannot
    /// match against the file's own source).
    #[test]
    fn no_legacy_loopback_iacs_literal_in_client_source() {
        let src = include_str!("proxy_iacs.rs");
        let needle = format!("{}.{}.{}.{}:{}", 127, 0, 0, 1, 4321);
        assert!(
            !src.contains(&needle),
            "legacy IACS MVP target literal must not appear in the IPC client"
        );
    }
}
