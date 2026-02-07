//! IPC client for communication with vauban-supervisor.
//!
//! Provides async methods to request TCP connections on behalf of
//! sandboxed services (Capsicum). The supervisor performs DNS resolution
//! and TCP connect, then passes the FD to the target service via SCM_RIGHTS.

use shared::ipc::IpcChannel;
use shared::messages::{ControlMessage, Message, Service, ServiceStats};
use std::collections::HashMap;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::oneshot;
use tracing::{debug, info, warn};

/// Pending TCP connect request waiting for response from supervisor.
struct PendingTcpConnect {
    /// Channel to send the response back to the caller.
    response_tx: oneshot::Sender<TcpConnectResult>,
}

/// Result of a TCP connect request.
#[derive(Debug)]
pub struct TcpConnectResult {
    /// Whether the connection was established successfully.
    pub success: bool,
    /// Error message if connection failed.
    pub error: Option<String>,
}

/// Shared state between the supervisor communication thread and async tasks.
pub struct SupervisorClientInner {
    /// IPC channel to supervisor.
    channel: IpcChannel,
    /// Next request ID for TCP connect requests.
    next_request_id: AtomicU64,
    /// Pending TCP connect requests.
    pending_tcp_connects: Mutex<HashMap<u64, PendingTcpConnect>>,
    /// Service statistics for heartbeat responses.
    pub start_time: Instant,
    pub requests_processed: AtomicU64,
    pub requests_failed: AtomicU64,
    /// Flag to stop the handler thread.
    shutdown: AtomicBool,
}

/// Async client for communication with the supervisor.
///
/// This client bridges the blocking IPC channel with the async runtime.
/// The IPC communication happens in a dedicated thread, while async tasks
/// use this client to send requests and await responses.
pub struct SupervisorClient {
    inner: Arc<SupervisorClientInner>,
    /// Handle to the handler thread (for shutdown).
    _thread_handle: std::thread::JoinHandle<()>,
}

impl SupervisorClient {
    /// Create a new supervisor client from IPC file descriptors.
    ///
    /// Spawns a dedicated thread for handling IPC communication.
    #[allow(clippy::panic)] // Thread spawn failure is unrecoverable
    pub fn new(read_fd: RawFd, write_fd: RawFd) -> Self {
        // Create IPC channel from file descriptors
        // SAFETY: FDs are passed from supervisor and are valid
        let channel = unsafe { IpcChannel::from_raw_fds(read_fd, write_fd) };

        let inner = Arc::new(SupervisorClientInner {
            channel,
            next_request_id: AtomicU64::new(1),
            pending_tcp_connects: Mutex::new(HashMap::new()),
            start_time: Instant::now(),
            requests_processed: AtomicU64::new(0),
            requests_failed: AtomicU64::new(0),
            shutdown: AtomicBool::new(false),
        });

        let thread_inner = Arc::clone(&inner);
        let thread_handle = std::thread::Builder::new()
            .name("supervisor-ipc".to_string())
            .spawn(move || {
                supervisor_ipc_loop(thread_inner);
            })
            .unwrap_or_else(|e| panic!("Failed to spawn supervisor IPC thread: {}", e));

        Self {
            inner,
            _thread_handle: thread_handle,
        }
    }

    /// Request the supervisor to establish a TCP connection.
    ///
    /// The supervisor performs DNS resolution and TCP connect, then passes
    /// the connected socket FD to the target service via SCM_RIGHTS.
    ///
    /// This method is async and waits for the supervisor's response.
    pub async fn request_tcp_connect(
        &self,
        session_id: &str,
        host: &str,
        port: u16,
        target_service: Service,
    ) -> Result<TcpConnectResult, String> {
        let request_id = self.inner.next_request_id.fetch_add(1, Ordering::SeqCst);

        debug!(
            request_id = request_id,
            session_id = %session_id,
            host = %host,
            port = port,
            ?target_service,
            "Requesting TCP connect from supervisor"
        );

        // Create response channel
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.inner.pending_tcp_connects.lock()
                .unwrap_or_else(|e| e.into_inner());
            pending.insert(request_id, PendingTcpConnect { response_tx: tx });
        }

        // Send request to supervisor
        let msg = Message::TcpConnectRequest {
            request_id,
            session_id: session_id.to_string(),
            host: host.to_string(),
            port,
            target_service,
        };

        if let Err(e) = self.inner.channel.send(&msg) {
            // Remove pending request on send error
            self.inner.pending_tcp_connects.lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&request_id);
            return Err(format!("Failed to send TcpConnectRequest: {}", e));
        }

        // Wait for response with timeout
        match tokio::time::timeout(Duration::from_secs(30), rx).await {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(_)) => {
                // Channel dropped (shouldn't happen)
                Err("Response channel dropped".to_string())
            }
            Err(_) => {
                // Timeout
                self.inner.pending_tcp_connects.lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&request_id);
                Err("TCP connect request timeout".to_string())
            }
        }
    }

    /// Get a reference to the shared inner state (for statistics).
    pub fn inner(&self) -> &Arc<SupervisorClientInner> {
        &self.inner
    }
}

/// Main loop for supervisor IPC communication thread.
///
/// Handles heartbeat pings from supervisor and routes TcpConnectResponse
/// to the appropriate waiting async tasks.
fn supervisor_ipc_loop(inner: Arc<SupervisorClientInner>) {
    use shared::ipc::poll_readable;

    let fds = [inner.channel.read_fd()];

    loop {
        if inner.shutdown.load(Ordering::Relaxed) {
            info!("Supervisor IPC thread shutting down");
            break;
        }

        // Wait for incoming messages with poll() - 1 second timeout
        let ready = match poll_readable(&fds, 1000) {
            Ok(r) => r,
            Err(e) => {
                warn!("Supervisor IPC poll error: {}", e);
                continue;
            }
        };

        if ready.is_empty() {
            // Timeout - continue loop
            continue;
        }

        // Read and handle message
        match inner.channel.recv() {
            Ok(Message::Control(ControlMessage::Ping { seq })) => {
                let stats = ServiceStats {
                    uptime_secs: inner.start_time.elapsed().as_secs(),
                    requests_processed: inner.requests_processed.load(Ordering::Relaxed),
                    requests_failed: inner.requests_failed.load(Ordering::Relaxed),
                    active_connections: 0, // TODO: track WebSocket connections
                    pending_requests: 0,
                };
                let pong = Message::Control(ControlMessage::Pong { seq, stats });
                if let Err(e) = inner.channel.send(&pong) {
                    warn!("Failed to send Pong: {}", e);
                }
            }
            Ok(Message::Control(ControlMessage::Shutdown)) => {
                info!("Shutdown requested by supervisor");
                std::process::exit(0);
            }
            Ok(Message::Control(ControlMessage::Drain)) => {
                info!("Drain requested by supervisor");
                // TODO: implement graceful drain
                let response = Message::Control(ControlMessage::DrainComplete {
                    pending_requests: 0,
                });
                let _ = inner.channel.send(&response);
            }
            Ok(Message::TcpConnectResponse {
                request_id,
                session_id,
                success,
                error,
            }) => {
                debug!(
                    request_id = request_id,
                    session_id = %session_id,
                    success = success,
                    "TCP connect response from supervisor"
                );

                // Route response to waiting task
                let pending = inner.pending_tcp_connects.lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&request_id);
                if let Some(pending) = pending {
                    let result = TcpConnectResult { success, error };
                    let _ = pending.response_tx.send(result);
                } else {
                    warn!(request_id = request_id, "No pending request for TCP connect response");
                }
            }
            Ok(_) => {
                // Other messages - ignore
            }
            Err(shared::ipc::IpcError::ConnectionClosed) => {
                info!("IPC connection closed, supervisor exited");
                std::process::exit(0);
            }
            Err(e) => {
                warn!("Supervisor IPC recv error: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_connect_result_success() {
        let result = TcpConnectResult {
            success: true,
            error: None,
        };
        assert!(result.success);
        assert!(result.error.is_none());
    }

    #[test]
    fn test_tcp_connect_result_failure() {
        let result = TcpConnectResult {
            success: false,
            error: Some("Connection refused".to_string()),
        };
        assert!(!result.success);
        assert_eq!(result.error.unwrap(), "Connection refused");
    }
}
