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

//! SCM_RIGHTS FD buffer for supervisor-brokered MCP upstream sockets (04 §4).

use shared::ipc::{poll_readable, recv_fd};
use std::collections::HashMap;
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::io::RawFd;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::{debug, warn};

pub type PendingConnections = Arc<Mutex<HashMap<String, OwnedFd>>>;

pub struct FdPassingState {
    pub socket_fd: RawFd,
    pub pending: PendingConnections,
}

/// Non-blocking receive with retry (same invariant as proxy-ssh / proxy-iacs).
pub async fn receive_fd_with_retry(
    socket_fd: RawFd,
    max_retries: u32,
    delay_ms: u64,
) -> Result<OwnedFd, shared::ipc::IpcError> {
    for attempt in 0..max_retries {
        match poll_readable(&[socket_fd], 0) {
            Ok(ready) if !ready.is_empty() => {
                return recv_fd(socket_fd);
            }
            Ok(_) => {
                if attempt < max_retries - 1 {
                    tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                }
            }
            Err(e) => {
                warn!(attempt, error = %e, "mcp_proxy: poll_readable failed");
                if attempt < max_retries - 1 {
                    tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                }
            }
        }
    }
    Err(shared::ipc::IpcError::Io(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!(
            "mcp_proxy: receive_fd_with_retry timed out after {max_retries} attempts \
             ({delay_ms} ms each); refusing blocking recv_fd"
        ),
    )))
}

pub async fn claim_pending(pending: &PendingConnections, session_id: &str) -> Option<OwnedFd> {
    let fd = pending.lock().await.remove(session_id);
    if fd.is_some() {
        debug!(session_id = %session_id, "claimed brokered upstream FD");
    }
    fd
}

/// Poll until the supervisor-stashed FD appears (TcpConnectResponse may
/// race slightly ahead of / behind McpSessionOpen).
pub async fn claim_pending_wait(
    pending: &PendingConnections,
    session_id: &str,
    timeout: Duration,
) -> Option<OwnedFd> {
    let deadline = tokio::time::Instant::now() + timeout;
    let poll = Duration::from_millis(20);
    loop {
        if let Some(fd) = claim_pending(pending, session_id).await {
            return Some(fd);
        }
        if tokio::time::Instant::now() >= deadline {
            warn!(
                session_id = %session_id,
                timeout_ms = timeout.as_millis(),
                "timed out waiting for brokered upstream FD"
            );
            return None;
        }
        tokio::time::sleep(poll).await;
    }
}

pub fn owned_fd_to_tcp_stream(fd: OwnedFd) -> io::Result<TcpStream> {
    let std_stream: std::net::TcpStream = fd.into();
    std_stream.set_nonblocking(true)?;
    TcpStream::from_std(std_stream)
}
