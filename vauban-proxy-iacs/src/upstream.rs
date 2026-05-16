//! Upstream TCP connection openers.
//!
//! `vauban-proxy-iacs` is sandboxed: post-`cap_enter` it cannot
//! `socket()` / `connect()` directly. Every upstream TCP connection
//! to an industrial asset goes through the supervisor's SCM_RIGHTS
//! broker:
//!
//! 1. The proxy emits `Message::TcpConnectRequest { host, port,
//!    target_service: ProxyIacs, session_id, session_token }` on
//!    its supervisor IPC pipe.
//! 2. The supervisor verifies the session token in
//!    `Verifier::Supervisor` role, DNS-resolves `host`, opens the
//!    TCP connection, and passes the connected FD back via
//!    SCM_RIGHTS on the FD-passing socket.
//! 3. The proxy receives the FD on its FD-passing socket,
//!    correlates it with the in-flight `session_id`, and converts
//!    it to a `tokio::net::TcpStream`.

use std::collections::HashMap;
use std::io;
use std::os::unix::io::OwnedFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use shared::messages::{Message, Service};
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, warn};

use crate::auth::PendingTunnel;
use crate::server::UpstreamOpener;

/// Pending TCP connections received from supervisor via FD passing.
/// Maps session_id -> pre-established TCP connection FD.
pub type PendingConnections = Arc<Mutex<HashMap<String, OwnedFd>>>;

/// Production opener: routes through the supervisor's SCM_RIGHTS
/// broker. The opener is constructed in `main_loop` after the
/// supervisor channel + pending-connections map are wired so it can:
///
/// 1. Push a `TcpConnectRequest` Message on `supervisor_tx`.
/// 2. Poll `pending_connections` for the SCM_RIGHTS FD that the
///    main loop's `TcpConnectResponse` handler stashes.
/// 3. Convert the `OwnedFd` into a `tokio::net::TcpStream`.
pub struct SupervisorBrokerOpener {
    /// Sender to push outbound `Message::TcpConnectRequest` on the
    /// supervisor IPC pipe. The main_loop owns the actual writer
    /// task; the opener never touches the pipe directly so we never
    /// race with concurrent senders.
    pub supervisor_tx: mpsc::UnboundedSender<Message>,
    /// FD-passing map populated by the main loop on every received
    /// `TcpConnectResponse` (success). Keyed on `session_id` so the
    /// opener can correlate.
    pub pending_connections: PendingConnections,
    /// How long to wait for the SCM_RIGHTS FD before failing the
    /// upstream open. Mirrors the SSH proxy's behaviour
    /// (poll-with-retry up to ~500 ms).
    pub fd_wait: Duration,
    /// Per-process monotonic counter for the `request_id` field of
    /// `TcpConnectRequest`. The supervisor broker uses it for
    /// correlation only; the proxy correlates by `session_id`.
    pub next_request_id: AtomicU64,
}

#[async_trait::async_trait]
impl UpstreamOpener for SupervisorBrokerOpener {
    async fn open(&self, pending: &PendingTunnel) -> io::Result<tokio::net::TcpStream> {
        let session_id = pending.session_uuid.to_string();
        let request_id = self.next_request_id.fetch_add(1, Ordering::SeqCst);
        let req = Message::TcpConnectRequest {
            request_id,
            session_id: session_id.clone(),
            host: pending.asset_host.clone(),
            port: pending.asset_port,
            target_service: Service::ProxyIacs,
            session_token: pending.session_token.clone(),
        };
        debug!(
            session_id = %session_id,
            host = %pending.asset_host,
            port = pending.asset_port,
            "iacs_tunnel: requesting TCP connect from supervisor"
        );
        self.supervisor_tx
            .send(req)
            .map_err(|e| io::Error::other(format!("supervisor_tx send: {e}")))?;

        // Poll the pending_connections map until the FD arrives or
        // the deadline passes. The main loop populates the entry
        // once it consumes a `TcpConnectResponse { success: true }`
        // and `recv_fd` returns the connected socket.
        let deadline = tokio::time::Instant::now() + self.fd_wait;
        let poll_interval = Duration::from_millis(20);
        loop {
            {
                let mut map = self.pending_connections.lock().await;
                if let Some(fd) = map.remove(&session_id) {
                    let std_stream: std::net::TcpStream = fd.into();
                    std_stream.set_nonblocking(true).map_err(|e| {
                        io::Error::other(format!(
                            "iacs_tunnel: set_nonblocking on brokered FD: {e}"
                        ))
                    })?;
                    let stream = tokio::net::TcpStream::from_std(std_stream).map_err(|e| {
                        io::Error::other(format!(
                            "iacs_tunnel: tokio TcpStream::from_std on brokered FD: {e}"
                        ))
                    })?;
                    debug!(
                        session_id = %session_id,
                        "iacs_tunnel: brokered upstream TCP socket converted to tokio stream"
                    );
                    return Ok(stream);
                }
            }
            if tokio::time::Instant::now() >= deadline {
                warn!(
                    session_id = %session_id,
                    timeout_ms = self.fd_wait.as_millis(),
                    "iacs_tunnel: timed out waiting for brokered FD"
                );
                return Err(io::Error::other(
                    "iacs_tunnel: timeout waiting for brokered upstream FD",
                ));
            }
            tokio::time::sleep(poll_interval).await;
        }
    }
}
