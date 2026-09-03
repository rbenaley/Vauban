//! IPC client for communication with vauban-supervisor.
//!
//! Provides async methods to request TCP connections on behalf of
//! sandboxed services (Capsicum). The supervisor performs DNS resolution
//! and TCP connect, then passes the FD to the target service via SCM_RIGHTS.
//!
//! # Correlation hygiene (0.9.31)
//!
//! Aligned on [`shared::correlated_ipc::PendingGuard`] /
//! [`CorrelatedIpcCore::insert_pending`] for the three pending maps
//! (TCP connect, recording file, recording delete). **Not** migrated to
//! AsyncFd `process_loop`: this client keeps a dedicated sync
//! `supervisor-ipc` thread with `poll` + SCM_RIGHTS demux (Ping, ACME,
//! Admin, TLS, FD passing).

use crate::services::broker_latency::BrokerLatencyTracker;
use shared::correlated_ipc::CorrelatedIpcCore;
use shared::ipc::{IpcChannel, recv_fd};
use shared::messages::{ControlMessage, Message, SensitiveString, Service, ServiceStats};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::unix::io::{FromRawFd, IntoRawFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::oneshot;
use tracing::{debug, info, warn};

/// TLS certificate data received from the supervisor via IPC.
pub struct TlsCertData {
    pub cert_pem: String,
    pub key_pem: SensitiveString,
}

/// Raw mapping-file provision received from the supervisor via IPC.
pub struct LdapMappingProvisionData {
    pub aggregation_enabled: bool,
    pub file_bytes: Vec<u8>,
}

/// One-shot boot channels handed back by [`SupervisorClient::new`].
pub struct SupervisorBootChannels {
    pub tls_cert_rx: std::sync::mpsc::Receiver<TlsCertData>,
    pub ldap_mapping_rx: std::sync::mpsc::Receiver<LdapMappingProvisionData>,
}

/// Result of a TCP connect request.
#[derive(Debug)]
pub struct TcpConnectResult {
    /// Whether the connection was established successfully.
    pub success: bool,
    /// Error message if connection failed.
    pub error: Option<String>,
}

/// Result of a recording file request.
#[derive(Debug)]
pub struct RecordingFileResult {
    pub success: bool,
    pub error: Option<String>,
    /// The opened file (present only on success).
    pub file: Option<std::fs::File>,
}

/// Result of a recording delete request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordingDeleteResult {
    pub success: bool,
    pub bytes_freed: u64,
    pub error: Option<String>,
}

/// Sync/`poll` supervisor IPC bridge (PendingGuard hygiene; not AsyncFd).
pub struct SupervisorClientInner {
    /// IPC channel to supervisor.
    pub channel: IpcChannel,
    /// FD passing socket for SCM_RIGHTS (recording files, etc.).
    fd_passing_socket: Option<RawFd>,
    /// Next request ID for TCP connect and recording file requests.
    /// Same monotonic allocator contract as [`CorrelatedIpcCore::alloc_id`].
    next_request_id: AtomicU64,
    /// Pending TCP connect requests (oneshot + PendingGuard GC).
    pending_tcp_connects: Mutex<HashMap<u64, oneshot::Sender<TcpConnectResult>>>,
    /// Pending recording file requests.
    pending_recording_files: Mutex<HashMap<u64, oneshot::Sender<RecordingFileResult>>>,
    /// Pending recording delete requests (retention reaper).
    pending_recording_deletes: Mutex<HashMap<u64, oneshot::Sender<RecordingDeleteResult>>>,
    /// Service statistics for heartbeat responses.
    pub start_time: Instant,
    pub requests_processed: AtomicU64,
    pub requests_failed: AtomicU64,
    /// Flag to stop the handler thread. Shared with IPC pumps so a
    /// supervisor-initiated shutdown is Quiet (no exit 100).
    shutdown: Arc<AtomicBool>,
    /// Server handle for triggering graceful shutdown.
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
    /// One-shot channel for receiving TLS cert data from supervisor at startup.
    tls_cert_tx: Mutex<Option<std::sync::mpsc::SyncSender<TlsCertData>>>,
    /// One-shot channel for receiving the LDAPS mapping file pre-seal.
    ldap_mapping_tx: Mutex<Option<std::sync::mpsc::SyncSender<LdapMappingProvisionData>>>,
    /// DB pool for admin command processing (set after pool creation).
    admin_db_pool: OnceLock<crate::db::DbPool>,
    /// Tokio runtime handle for running async admin commands from the sync IPC thread.
    tokio_handle: OnceLock<tokio::runtime::Handle>,
    /// Sliding-window tracker for supervisor-brokered round-trip
    /// latency. Updated from `request_tcp_connect` on success; consumed
    /// by the Bastion Watch dashboard's "FD-passing latency" tile.
    pub broker_latency: Arc<BrokerLatencyTracker>,
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
    /// The optional `server_handle` is used for graceful shutdown:
    /// instead of calling `process::exit(0)`, the IPC thread will trigger
    /// graceful HTTP server shutdown, allowing all destructors to run.
    ///
    #[allow(clippy::panic)] // Thread spawn failure is unrecoverable
    pub fn new(
        read_fd: RawFd,
        write_fd: RawFd,
        fd_passing_socket: Option<RawFd>,
        server_handle: Option<axum_server::Handle<SocketAddr>>,
    ) -> (Self, SupervisorBootChannels) {
        // Create IPC channel from file descriptors
        // SAFETY: FDs are passed from supervisor and are valid
        let channel = unsafe { IpcChannel::from_raw_fds(read_fd, write_fd) };

        let (tls_cert_tx, tls_cert_rx) = std::sync::mpsc::sync_channel(1);
        let (ldap_mapping_tx, ldap_mapping_rx) = std::sync::mpsc::sync_channel(1);

        let inner = Arc::new(SupervisorClientInner {
            channel,
            fd_passing_socket,
            next_request_id: AtomicU64::new(1),
            pending_tcp_connects: Mutex::new(HashMap::new()),
            pending_recording_files: Mutex::new(HashMap::new()),
            pending_recording_deletes: Mutex::new(HashMap::new()),
            start_time: Instant::now(),
            requests_processed: AtomicU64::new(0),
            requests_failed: AtomicU64::new(0),
            shutdown: Arc::new(AtomicBool::new(false)),
            server_handle,
            acme_resolver: OnceLock::new(),
            cert_expiry: OnceLock::new(),
            tls_cert_tx: Mutex::new(Some(tls_cert_tx)),
            ldap_mapping_tx: Mutex::new(Some(ldap_mapping_tx)),
            admin_db_pool: OnceLock::new(),
            tokio_handle: OnceLock::new(),
            broker_latency: Arc::new(BrokerLatencyTracker::default()),
        });

        let thread_inner = Arc::clone(&inner);
        let thread_handle = std::thread::Builder::new()
            .name("supervisor-ipc".to_string())
            .spawn(move || {
                supervisor_ipc_loop(thread_inner);
            })
            .unwrap_or_else(|e| panic!("Failed to spawn supervisor IPC thread: {}", e));

        (
            Self {
                inner,
                _thread_handle: thread_handle,
            },
            SupervisorBootChannels {
                tls_cert_rx,
                ldap_mapping_rx,
            },
        )
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
        session_token: Vec<u8>,
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

        // Broker latency stopwatch: started right before we hand the
        // request off to the supervisor IPC channel and stopped when
        // we observe a successful response. Failure / timeout paths
        // intentionally skip the record() so a misbehaving target
        // (closed port, DNS failure) does not skew the dashboard p95.
        let started_at = Instant::now();

        let (tx, rx) = oneshot::channel();
        let _guard =
            CorrelatedIpcCore::insert_pending(&self.inner.pending_tcp_connects, request_id, tx);

        let msg = Message::TcpConnectRequest {
            request_id,
            session_id: session_id.to_string(),
            host: host.to_string(),
            port,
            target_service,
            session_token,
        };

        if let Err(e) = self.inner.channel.send(&msg) {
            // PendingGuard Drop GC on return
            return Err(format!("Failed to send TcpConnectRequest: {}", e));
        }

        match tokio::time::timeout(Duration::from_secs(30), rx).await {
            Ok(Ok(result)) => {
                if result.success {
                    self.inner.broker_latency.record(started_at.elapsed());
                }
                Ok(result)
            }
            Ok(Err(_)) => Err("Response channel dropped".to_string()),
            Err(_) => Err("TCP connect request timeout".to_string()),
        }
    }

    /// Request the supervisor to open a recording file (read-only) and pass
    /// the FD via SCM_RIGHTS. Returns the opened file on success.
    pub async fn request_recording_file(
        &self,
        session_id: &str,
        relative_path: &str,
    ) -> Result<RecordingFileResult, String> {
        let request_id = self.inner.next_request_id.fetch_add(1, Ordering::SeqCst);

        debug!(
            request_id,
            session_id = %session_id,
            path = %relative_path,
            "Requesting recording file from supervisor (read-only)"
        );

        let (tx, rx) = oneshot::channel();
        let _guard =
            CorrelatedIpcCore::insert_pending(&self.inner.pending_recording_files, request_id, tx);

        let msg = Message::RecordingFileRequest {
            request_id,
            session_id: session_id.to_string(),
            relative_path: relative_path.to_string(),
            read_only: true,
        };

        if let Err(e) = self.inner.channel.send(&msg) {
            return Err(format!("Failed to send RecordingFileRequest: {}", e));
        }

        match tokio::time::timeout(Duration::from_secs(10), rx).await {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(_)) => Err("Response channel dropped".to_string()),
            Err(_) => Err("Recording file request timeout".to_string()),
        }
    }

    /// Request the supervisor to delete a recording directory or legacy file.
    pub async fn request_recording_delete(
        &self,
        session_id: &str,
        relative_path: &str,
    ) -> Result<RecordingDeleteResult, String> {
        let request_id = self.inner.next_request_id.fetch_add(1, Ordering::SeqCst);

        debug!(
            request_id,
            session_id = %session_id,
            path = %relative_path,
            "Requesting recording delete from supervisor"
        );

        let (tx, rx) = oneshot::channel();
        let _guard = CorrelatedIpcCore::insert_pending(
            &self.inner.pending_recording_deletes,
            request_id,
            tx,
        );

        let msg = Message::RecordingDeleteRequest {
            request_id,
            session_id: session_id.to_string(),
            relative_path: relative_path.to_string(),
        };

        if let Err(e) = self.inner.channel.send(&msg) {
            return Err(format!("Failed to send RecordingDeleteRequest: {}", e));
        }

        match tokio::time::timeout(Duration::from_secs(30), rx).await {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(_)) => Err("Response channel dropped".to_string()),
            Err(_) => Err("Recording delete request timeout".to_string()),
        }
    }

    /// Get a reference to the shared inner state (for statistics).
    pub fn inner(&self) -> &Arc<SupervisorClientInner> {
        &self.inner
    }

    /// Clone the supervisor-shutdown latch (shared with IPC pumps).
    pub fn shutdown_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.inner.shutdown)
    }

    /// Reference to the broker latency tracker shared with the
    /// dashboard's "FD-passing latency" tile.
    pub fn broker_latency(&self) -> &Arc<BrokerLatencyTracker> {
        &self.inner.broker_latency
    }

    /// Get the raw FD passing socket (for receiving the listening socket from supervisor).
    pub fn fd_passing_socket(&self) -> Option<RawFd> {
        self.inner.fd_passing_socket
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

    /// Register the DB pool for admin command processing via IPC.
    pub fn set_admin_pool(&self, pool: crate::db::DbPool) {
        if self.inner.admin_db_pool.set(pool).is_err() {
            warn!("Admin DB pool already set, ignoring duplicate");
        }
    }

    /// Register the Tokio runtime handle for running async admin commands.
    pub fn set_tokio_handle(&self, handle: tokio::runtime::Handle) {
        if self.inner.tokio_handle.set(handle).is_err() {
            warn!("Tokio handle already set, ignoring duplicate");
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
                    recording_ack_timeouts: 0,
                    recording_ack_dropped: 0,
                    recording_try_send_full: 0,
                    recording_ack_wait_ms_max: 0,
                };
                let pong = Message::Control(ControlMessage::Pong { seq, stats });
                if let Err(e) = inner.channel.send(&pong) {
                    warn!("Failed to send Pong: {}", e);
                }
            }
            Ok(Message::Control(ControlMessage::Shutdown)) => {
                info!("Shutdown requested by supervisor, triggering graceful shutdown");
                // Trigger graceful HTTP server shutdown instead of exit(0).
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

                let result = TcpConnectResult { success, error };
                if !CorrelatedIpcCore::deliver(&inner.pending_tcp_connects, request_id, result) {
                    warn!(
                        request_id = request_id,
                        "No pending request for TCP connect response"
                    );
                }
            }
            Ok(Message::RecordingFileResponse {
                request_id,
                session_id,
                success,
                error,
            }) => {
                debug!(
                    request_id,
                    session_id = %session_id,
                    success,
                    "Recording file response from supervisor"
                );

                let file = if success {
                    if let Some(fd_socket) = inner.fd_passing_socket {
                        match recv_fd(fd_socket) {
                            Ok(owned_fd) => {
                                // SAFETY: fd received via SCM_RIGHTS from supervisor
                                Some(unsafe { std::fs::File::from_raw_fd(owned_fd.into_raw_fd()) })
                            }
                            Err(e) => {
                                warn!(request_id, error = %e, "Failed to recv_fd for recording file");
                                None
                            }
                        }
                    } else {
                        warn!(request_id, "No fd_passing socket configured");
                        None
                    }
                } else {
                    None
                };

                let result = RecordingFileResult {
                    success: success && file.is_some(),
                    error: if file.is_none() && success {
                        Some("recv_fd failed".to_string())
                    } else {
                        error
                    },
                    file,
                };
                if !CorrelatedIpcCore::deliver(&inner.pending_recording_files, request_id, result) {
                    warn!(request_id, "No pending request for recording file response");
                }
            }
            Ok(Message::RecordingDeleteResponse {
                request_id,
                session_id,
                success,
                bytes_freed,
                error,
            }) => {
                debug!(
                    request_id,
                    session_id = %session_id,
                    success,
                    bytes_freed,
                    "Recording delete response from supervisor"
                );

                let result = RecordingDeleteResult {
                    success,
                    bytes_freed,
                    error,
                };
                if !CorrelatedIpcCore::deliver(&inner.pending_recording_deletes, request_id, result)
                {
                    warn!(
                        request_id,
                        "No pending request for recording delete response"
                    );
                }
            }
            Ok(Message::TlsCertProvision { cert_pem, key_pem }) => {
                info!("Received TLS certificate data from supervisor");
                let tx = inner
                    .tls_cert_tx
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .take();
                if let Some(tx) = tx {
                    let _ = tx.send(TlsCertData { cert_pem, key_pem });
                } else {
                    warn!(
                        "TlsCertProvision received but no receiver (already consumed or duplicate)"
                    );
                }
            }
            Ok(Message::WebLdapMappingProvision {
                aggregation_enabled,
                file_bytes,
            }) => {
                info!(
                    aggregation_enabled,
                    bytes = file_bytes.len(),
                    "Received LDAP mapping provision from supervisor"
                );
                let tx = inner
                    .ldap_mapping_tx
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .take();
                if let Some(tx) = tx {
                    let _ = tx.send(LdapMappingProvisionData {
                        aggregation_enabled,
                        file_bytes,
                    });
                } else {
                    warn!(
                        "WebLdapMappingProvision received but no receiver (already consumed or duplicate)"
                    );
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
                    match crate::acme::resolver::certified_key_from_pem(&cert_pem, key_pem.as_str())
                    {
                        Ok(certified_key) => {
                            resolver.activate_production_cert(Arc::new(certified_key));
                            // Update in-memory expiry tracker from the new certificate
                            if let Some(expiry) = inner.cert_expiry.get() {
                                use rustls_pki_types::CertificateDer;
                                use rustls_pki_types::pem::PemObject;
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
            Ok(Message::AdminCommand {
                request_id,
                command,
            }) => {
                info!(request_id, cmd = ?std::mem::discriminant(&command), "Admin command received");
                let response = match (inner.admin_db_pool.get(), inner.tokio_handle.get()) {
                    (Some(pool), Some(handle)) => {
                        handle.block_on(super::admin::handle_admin_command(pool, command))
                    }
                    _ => {
                        warn!("Admin command received but DB pool or Tokio handle not configured");
                        shared::messages::AdminResponse::Error(
                            "Service not ready for admin commands".to_string(),
                        )
                    }
                };
                let msg = Message::AdminResponse {
                    request_id,
                    response,
                };
                if let Err(e) = inner.channel.send(&msg) {
                    warn!(request_id, error = %e, "Failed to send AdminResponse");
                }
            }
            Ok(_) => {
                // Other messages - ignore
            }
            Err(shared::ipc::IpcError::ConnectionClosed) => {
                info!("IPC connection closed, supervisor exited, triggering graceful shutdown");
                // Trigger graceful HTTP server shutdown instead of exit(0).
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
impl SupervisorClient {
    /// Test-only pending-map sizes (must not be used for production control).
    ///
    /// Kept in a dedicated `#[cfg(test)] impl` block so source-grep helpers
    /// that truncate at the first `#[cfg(test)]` still see the production
    /// `supervisor_ipc_loop` (graceful_shutdown, etc.).
    fn pending_counts_for_test(&self) -> (usize, usize, usize) {
        let tcp = self
            .inner
            .pending_tcp_connects
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len();
        let files = self
            .inner
            .pending_recording_files
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len();
        let deletes = self
            .inner
            .pending_recording_deletes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len();
        (tcp, files, deletes)
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
    fn test_tls_cert_data_stores_pem() {
        let data = TlsCertData {
            cert_pem: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----".to_string(),
            key_pem: SensitiveString::new(
                "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----".to_string(),
            ),
        };
        assert!(data.cert_pem.contains("CERTIFICATE"));
        assert!(data.key_pem.as_str().contains("PRIVATE KEY"));
    }

    #[test]
    fn test_tls_cert_provision_handled_in_ipc_loop() {
        let source = include_str!("supervisor.rs");
        assert!(
            source.contains("Message::TlsCertProvision"),
            "supervisor_ipc_loop must handle TlsCertProvision"
        );
        assert!(
            source.contains("tls_cert_tx"),
            "TlsCertProvision handler must use tls_cert_tx channel"
        );
        assert!(
            source.contains("Message::WebLdapMappingProvision"),
            "supervisor_ipc_loop must handle WebLdapMappingProvision"
        );
        assert!(
            source.contains("ldap_mapping_tx"),
            "WebLdapMappingProvision handler must use ldap_mapping_tx"
        );
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

    #[test]
    fn request_paths_install_insert_pending() {
        let source = include_str!("supervisor.rs");
        let prod = source.split("#[cfg(test)]").next().expect("prod");
        let count = prod.matches("CorrelatedIpcCore::insert_pending").count();
        assert!(
            count >= 3,
            "each of the 3 request_* paths must call insert_pending, found {count}"
        );
        assert!(
            !prod.contains("AsyncFd::"),
            "SupervisorClient must not use AsyncFd"
        );
        // Split literal so this pin file does not itself match the lint needle.
        let forbidden = format!(".{}(", "process_loop");
        assert!(
            !prod.contains(&forbidden),
            "SupervisorClient must not use process_loop"
        );
    }

    /// Closed peer ends: `channel.send` fails; PendingGuard Drop must
    /// leave all three maps empty (no manual remove required).
    fn closed_peer_client() -> SupervisorClient {
        use std::os::unix::io::IntoRawFd;
        let (c_read, c_write) = nix::unistd::pipe().expect("pipe");
        let (d_read, d_write) = nix::unistd::pipe().expect("pipe");
        let read_fd = c_read.into_raw_fd();
        let write_fd = d_write.into_raw_fd();
        drop(c_write);
        drop(d_read);
        let (client, _boot) = SupervisorClient::new(read_fd, write_fd, None, None);
        client
    }

    #[tokio::test]
    async fn battle_tcp_connect_send_fail_clears_pending() {
        let client = closed_peer_client();
        let _ = client
            .request_tcp_connect("sess", "127.0.0.1", 22, Service::ProxySsh, vec![1])
            .await
            .expect_err("send fail");
        assert_eq!(client.pending_counts_for_test(), (0, 0, 0));
    }

    #[tokio::test]
    async fn battle_recording_file_send_fail_clears_pending() {
        let client = closed_peer_client();
        let _ = client
            .request_recording_file("sess", "rec/x.cast")
            .await
            .expect_err("send fail");
        assert_eq!(client.pending_counts_for_test(), (0, 0, 0));
    }

    #[tokio::test]
    async fn battle_recording_delete_send_fail_clears_pending() {
        let client = closed_peer_client();
        let _ = client
            .request_recording_delete("sess", "rec/x")
            .await
            .expect_err("send fail");
        assert_eq!(client.pending_counts_for_test(), (0, 0, 0));
    }
}
