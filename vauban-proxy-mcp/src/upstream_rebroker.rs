// Relax strict clippy lints in test code where unwrap/expect/panic are idiomatic.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::print_stdout,
        clippy::print_stderr
    )
)]

//! IACS-style re-broker: when the hop-1 upstream TCP dies, the proxy
//! asks the supervisor for a new FD (same session token / host / port).
//! No free `connect()`. One retry of the HTTP POST.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use shared::messages::{Message, Service};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::fd_passing::{PendingConnections, claim_pending_wait, owned_fd_to_tcp_stream};

/// True when the brokered HTTP stream is gone (peer close / EPIPE).
pub fn is_dead_upstream_io(err: &anyhow::Error) -> bool {
    use std::io::ErrorKind;
    if let Some(ioe) = err.downcast_ref::<io::Error>() {
        return matches!(
            ioe.kind(),
            ErrorKind::BrokenPipe
                | ErrorKind::ConnectionReset
                | ErrorKind::UnexpectedEof
                | ErrorKind::ConnectionAborted
        );
    }
    let s = format!("{err:#}");
    s.contains("upstream closed before HTTP headers")
        || s.contains("Broken pipe")
        || s.contains("os error 32")
        || s.contains("Connection reset")
}

pub struct McpUpstreamRebroker {
    pub supervisor_tx: mpsc::UnboundedSender<Message>,
    pub pending: PendingConnections,
    pub next_request_id: AtomicU64,
    pub fd_wait: Duration,
}

impl McpUpstreamRebroker {
    pub fn new(supervisor_tx: mpsc::UnboundedSender<Message>, pending: PendingConnections) -> Self {
        Self {
            supervisor_tx,
            pending,
            next_request_id: AtomicU64::new(1),
            fd_wait: Duration::from_secs(5),
        }
    }

    /// Same token as hop 1. Supervisor replay is bypassed for ProxyMcp.
    pub async fn open(
        &self,
        session_id: &str,
        host: &str,
        port: u16,
        session_token: &[u8],
    ) -> io::Result<TcpStream> {
        if host.is_empty() || port == 0 || session_token.is_empty() {
            return Err(io::Error::other(
                "mcp rebroker: missing host/port/session_token",
            ));
        }
        let request_id = self.next_request_id.fetch_add(1, Ordering::SeqCst);
        let req = Message::TcpConnectRequest {
            request_id,
            session_id: session_id.to_string(),
            host: host.to_string(),
            port,
            target_service: Service::ProxyMcp,
            session_token: session_token.to_vec(),
        };
        self.supervisor_tx
            .send(req)
            .map_err(|e| io::Error::other(format!("mcp rebroker supervisor_tx: {e}")))?;
        info!(
            session_id = %session_id,
            host = %host,
            port,
            "mcp rebroker: TcpConnectRequest (IACS-style multi-use)"
        );
        match claim_pending_wait(&self.pending, session_id, self.fd_wait).await {
            Some(fd) => owned_fd_to_tcp_stream(fd),
            None => {
                warn!(
                    session_id = %session_id,
                    "mcp rebroker: timed out waiting for brokered FD"
                );
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "mcp rebroker: no brokered FD",
                ))
            }
        }
    }
}

#[cfg(test)]
#[path = "upstream_rebroker_tests.rs"]
mod tests;
