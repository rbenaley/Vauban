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
//! (`IacsTunnelTerminate`) used by the revocation watchdog, and a
//! status-update notification (`IacsTunnelStatusUpdate` /
//! `IacsTunnelClosed`) that proxy-iacs pushes on its own when the
//! lifecycle changes. See [`shared/src/messages.rs`] for the full
//! definitions, and the per-asset target plan in
//! `.cursor/plans/iacs_proxy_per-asset_target_efa20838.plan.md`.

use crate::error::{AppError, AppResult};
use crate::services::broadcast::{BroadcastService, WsChannel};
use serde_json::json;
use shared::ipc::IpcChannel;
use shared::messages::Message;
use std::collections::HashMap;
use std::io;
use std::os::unix::io::RawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
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
    /// ...). Currently used only for forensic logs; future versions
    /// may use it to gate `direct-tcpip` per-protocol.
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
    /// Optional broadcast handle, set by
    /// [`ProxyIacsClient::process_incoming_with_broadcast`] before
    /// the loop starts. When present, every incoming
    /// `IacsTunnelStatusUpdate` / `IacsTunnelClosed` is fanned out
    /// on `WsChannel::SessionLive(<session_id>)` so the status page
    /// flips between `waiting_client` -> `tunnel_active` ->
    /// `tunnel_closed` in real time without DB polling.
    broadcast: Mutex<Option<BroadcastService>>,
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
            broadcast: Mutex::new(None),
        }))
    }

    /// Like [`Self::process_incoming`] but stashes a broadcast
    /// handle first so `IacsTunnelStatusUpdate` / `IacsTunnelClosed`
    /// notifications can be fanned out to the per-session WebSocket
    /// channel.
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
    pub async fn open_tunnel(
        &self,
        request: IacsTunnelOpenRequest,
    ) -> AppResult<IacsTunnelOpened> {
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

    /// Drain incoming messages from the proxy.
    ///
    /// Run forever in a dedicated task. Closes the loop on a
    /// `ConnectionClosed` IPC error (proxy-iacs respawn).
    pub async fn process_incoming(&self) -> AppResult<()> {
        loop {
            let mut guard = self
                .read_async_fd
                .ready(Interest::READABLE)
                .await
                .map_err(|e| AppError::Ipc(format!("AsyncFd ready failed: {}", e)))?;

            loop {
                match self.channel.try_recv() {
                    Ok(msg) => {
                        self.handle_message(msg).await;
                    }
                    Err(shared::ipc::IpcError::Io(ref e))
                        if e.kind() == io::ErrorKind::WouldBlock =>
                    {
                        guard.clear_ready();
                        break;
                    }
                    Err(shared::ipc::IpcError::ConnectionClosed) => {
                        info!("IACS proxy IPC connection closed");
                        return Err(AppError::Ipc("IPC connection closed".to_string()));
                    }
                    Err(e) => {
                        error!(error = %e, "IPC receive error");
                        guard.clear_ready();
                        break;
                    }
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

            // Status updates from proxy-iacs (Lot 5). Fanned out on
            // the per-session `WsChannel::SessionLive(<session_id>)`
            // so the status page flips status pills + byte counters
            // without DB polling. The channel is parametric (one
            // instance per session) so the broadcast level is
            // `debug!` per `websocket-logging.mdc`.
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
                let payload = json!({
                    "type": "iacs_tunnel_status",
                    "session_id": session_id,
                    "status": status,
                    "bytes_in": bytes_in,
                    "bytes_out": bytes_out,
                    "peer_ip": peer_ip,
                });
                let channel_name =
                    WsChannel::SessionLive(session_id.clone()).as_str();
                if let Some(b) = self.broadcast.lock().await.as_ref() {
                    let _ = b.send_raw(&channel_name, payload.to_string()).await;
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
                let payload = json!({
                    "type": "iacs_tunnel_closed",
                    "session_id": session_id,
                    "reason": reason,
                    "bytes_in": bytes_in,
                    "bytes_out": bytes_out,
                    "peer_ip": peer_ip,
                });
                let channel_name =
                    WsChannel::SessionLive(session_id.clone()).as_str();
                if let Some(b) = self.broadcast.lock().await.as_ref() {
                    let _ = b.send_raw(&channel_name, payload.to_string()).await;
                }
            }

            _ => {
                warn!(?msg, "Ignoring unexpected message from proxy-iacs");
            }
        }
    }
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
