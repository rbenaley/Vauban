//! IPC client for communication with vauban-supervisor.
//!
//! Provides async methods to request TCP connections on behalf of
//! sandboxed services (Capsicum). The supervisor performs DNS resolution
//! and TCP connect, then passes the FD to the target service via SCM_RIGHTS.

use shared::ipc::IpcChannel;
use shared::messages::{ControlMessage, Message, Service, ServiceStats};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
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
    pub channel: IpcChannel,
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
    /// M-8/M-10: Server handle for triggering graceful shutdown.
    /// When the supervisor requests shutdown or IPC closes, we use this
    /// to stop the HTTP server instead of calling process::exit(0).
    server_handle: Option<axum_server::Handle<SocketAddr>>,
    /// ACME dynamic TLS resolver for certificate updates via IPC.
    /// Set after TLS config loading via `set_acme_resolver()`.
    /// When set, the IPC loop processes AcmeChallengeInstall/Remove
    /// and AcmeCertActivate messages to update certificates in-memory.
    acme_resolver: OnceLock<Arc<crate::acme::resolver::AcmeResolver>>,
    /// ACME certificate expiry tracker, updated when AcmeCertActivate arrives.
    /// Extracted before cap_enter() and decremented between monitoring ticks.
    cert_expiry: OnceLock<Arc<crate::tasks::CertExpiry>>,
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
    /// The optional `server_handle` is used for M-8/M-10 graceful shutdown:
    /// instead of calling `process::exit(0)`, the IPC thread will trigger
    /// graceful HTTP server shutdown, allowing all destructors to run.
    ///
    #[allow(clippy::panic)] // Thread spawn failure is unrecoverable
    pub fn new(
        read_fd: RawFd,
        write_fd: RawFd,
        server_handle: Option<axum_server::Handle<SocketAddr>>,
    ) -> Self {
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
            server_handle,
            acme_resolver: OnceLock::new(),
            cert_expiry: OnceLock::new(),
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

    /// Set the ACME resolver for dynamic certificate management.
    ///
    /// Must be called after TLS configuration is loaded (Phase 1) and before
    /// ACME monitoring tasks start (Phase 3). Can only be called once.
    pub fn set_acme_resolver(&self, resolver: Arc<crate::acme::resolver::AcmeResolver>) {
        if self.inner.acme_resolver.set(resolver).is_err() {
            warn!("ACME resolver already set, ignoring duplicate");
        } else {
            info!("ACME resolver registered with supervisor IPC handler");
        }
    }

    /// Register the certificate expiry tracker for updates on AcmeCertActivate.
    pub fn set_cert_expiry(&self, expiry: Arc<crate::tasks::CertExpiry>) {
        if self.inner.cert_expiry.set(expiry).is_err() {
            warn!("Certificate expiry tracker already set, ignoring duplicate");
        }
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
                info!("Shutdown requested by supervisor, triggering graceful shutdown");
                // M-8/M-10: Trigger graceful HTTP server shutdown instead of exit(0).
                // This allows all Drop/Zeroize destructors to run.
                if let Some(ref handle) = inner.server_handle {
                    handle.graceful_shutdown(Some(Duration::from_secs(10)));
                }
                inner.shutdown.store(true, Ordering::SeqCst);
                break;
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
            Ok(Message::AcmeChallengeInstall {
                request_id: _,
                domain,
                challenge_cert_der,
                challenge_key_der,
            }) => {
                if let Some(resolver) = inner.acme_resolver.get() {
                    match crate::acme::resolver::certified_key_from_der(
                        &challenge_cert_der,
                        &challenge_key_der,
                    ) {
                        Ok(certified_key) => {
                            resolver.install_challenge(&domain, Arc::new(certified_key));
                            info!(domain = %domain, "ACME challenge certificate installed");
                        }
                        Err(e) => {
                            warn!(
                                domain = %domain,
                                error = %e,
                                "Failed to parse ACME challenge certificate"
                            );
                        }
                    }
                } else {
                    warn!("Received AcmeChallengeInstall but no ACME resolver configured");
                }
            }
            Ok(Message::AcmeChallengeRemove {
                request_id: _,
                domain,
            }) => {
                if let Some(resolver) = inner.acme_resolver.get() {
                    resolver.remove_challenge(&domain);
                } else {
                    warn!("Received AcmeChallengeRemove but no ACME resolver configured");
                }
            }
            Ok(Message::AcmeCertActivate {
                request_id: _,
                cert_pem,
                key_pem,
            }) => {
                if let Some(resolver) = inner.acme_resolver.get() {
                    match crate::acme::resolver::certified_key_from_pem(
                        &cert_pem,
                        key_pem.as_str(),
                    ) {
                        Ok(certified_key) => {
                            resolver.activate_production_cert(Arc::new(certified_key));
                            // Update in-memory expiry tracker from the new certificate
                            if let Some(expiry) = inner.cert_expiry.get() {
                                use rustls_pki_types::pem::PemObject;
                                use rustls_pki_types::CertificateDer;
                                let certs: Vec<CertificateDer<'static>> =
                                    CertificateDer::pem_slice_iter(cert_pem.as_bytes())
                                        .filter_map(|c| c.ok())
                                        .collect();
                                if let Some(cert_der) = certs.first() {
                                    expiry.update_from_der(cert_der.as_ref());
                                }
                            }
                            info!("New ACME production certificate activated (zero-downtime)");
                        }
                        Err(e) => {
                            warn!(error = %e, "Failed to parse new ACME production certificate");
                        }
                    }
                } else {
                    warn!("Received AcmeCertActivate but no ACME resolver configured");
                }
            }
            Ok(Message::AcmeRenewResponse {
                request_id: _,
                success,
                error,
                ..
            }) => {
                if success {
                    info!("ACME renewal completed successfully");
                } else {
                    warn!(
                        error = ?error,
                        "ACME renewal failed"
                    );
                }
            }
            Ok(_) => {
                // Other messages - ignore
            }
            Err(shared::ipc::IpcError::ConnectionClosed) => {
                info!("IPC connection closed, supervisor exited, triggering graceful shutdown");
                // M-8/M-10: Trigger graceful HTTP server shutdown instead of exit(0).
                if let Some(ref handle) = inner.server_handle {
                    handle.graceful_shutdown(Some(Duration::from_secs(10)));
                }
                inner.shutdown.store(true, Ordering::SeqCst);
                break;
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
