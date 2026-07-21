//! IPC client for communication with vauban-supervisor.
//!
//! Provides async methods to request TCP connections on behalf of
//! sandboxed services (Capsicum). The supervisor performs DNS resolution
//! and TCP connect, then passes the FD to the target service via SCM_RIGHTS.

use crate::services::broker_latency::BrokerLatencyTracker;
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

/// Pending recording file request waiting for response from supervisor.
struct PendingRecordingFile {
    response_tx: oneshot::Sender<RecordingFileResult>,
}

/// Result of a recording file request.
#[derive(Debug)]
pub struct RecordingFileResult {
    pub success: bool,
    pub error: Option<String>,
    /// The opened file (present only on success).
    pub file: Option<std::fs::File>,
}

/// Pending recording delete request waiting for response from supervisor.
struct PendingRecordingDelete {
    response_tx: oneshot::Sender<RecordingDeleteResult>,
}

/// Result of a recording delete request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordingDeleteResult {
    pub success: bool,
    pub bytes_freed: u64,
    pub error: Option<String>,
}

/// Pending SMTP broker request (Issue #10) waiting for the supervisor
/// to come back with a connected `tokio::net::TcpStream` materialised
/// from a SCM_RIGHTS file descriptor.
struct PendingSmtpConnect {
    response_tx: oneshot::Sender<SmtpConnectResult>,
}

/// Result of an SMTP-broker request.
///
/// `stream` is `Some` iff `success` is true; the supervisor performed
/// DNS + connect, validated the `(host, port)` against its `[mailer]`
/// whitelist, and passed the connected FD via SCM_RIGHTS. The stream
/// is non-blocking and ready for use with `tokio-rustls` STARTTLS or
/// direct AUTH/MAIL/RCPT/DATA exchange.
pub struct SmtpConnectResult {
    pub success: bool,
    pub error: Option<String>,
    pub stream: Option<tokio::net::TcpStream>,
}

impl std::fmt::Debug for SmtpConnectResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmtpConnectResult")
            .field("success", &self.success)
            .field("error", &self.error)
            .field("stream", &self.stream.as_ref().map(|_| "<TcpStream>"))
            .finish()
    }
}

/// Shared state between the supervisor communication thread and async tasks.
pub struct SupervisorClientInner {
    /// IPC channel to supervisor.
    pub channel: IpcChannel,
    /// FD passing socket for SCM_RIGHTS (recording files, etc.).
    fd_passing_socket: Option<RawFd>,
    /// Next request ID for TCP connect and recording file requests.
    next_request_id: AtomicU64,
    /// Pending TCP connect requests.
    pending_tcp_connects: Mutex<HashMap<u64, PendingTcpConnect>>,
    /// Pending recording file requests.
    pending_recording_files: Mutex<HashMap<u64, PendingRecordingFile>>,
    /// Pending recording delete requests (retention reaper).
    pending_recording_deletes: Mutex<HashMap<u64, PendingRecordingDelete>>,
    /// Pending SMTP-broker requests (Issue #10). Distinct from
    /// `pending_tcp_connects` because the IPC loop must materialise an
    /// FD via SCM_RIGHTS into a `tokio::net::TcpStream` for these,
    /// whereas `pending_tcp_connects` is fire-and-forget on the web
    /// side (the proxy receives the FD).
    pending_smtp_connects: Mutex<HashMap<u64, PendingSmtpConnect>>,
    /// Service statistics for heartbeat responses.
    pub start_time: Instant,
    pub requests_processed: AtomicU64,
    pub requests_failed: AtomicU64,
    /// Flag to stop the handler thread.
    shutdown: AtomicBool,
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
    /// DB pool for admin command processing (set after pool creation).
    admin_db_pool: OnceLock<crate::db::DbPool>,
    /// Tokio runtime handle for running async admin commands from the sync IPC thread.
    tokio_handle: OnceLock<tokio::runtime::Handle>,
    /// Sliding-window tracker for supervisor-brokered round-trip
    /// latency. Updated from `request_tcp_connect` /
    /// `request_smtp_connect` on success; consumed by the Bastion
    /// Watch dashboard's "FD-passing latency" tile.
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
    ) -> (Self, std::sync::mpsc::Receiver<TlsCertData>) {
        // Create IPC channel from file descriptors
        // SAFETY: FDs are passed from supervisor and are valid
        let channel = unsafe { IpcChannel::from_raw_fds(read_fd, write_fd) };

        let (tls_cert_tx, tls_cert_rx) = std::sync::mpsc::sync_channel(1);

        let inner = Arc::new(SupervisorClientInner {
            channel,
            fd_passing_socket,
            next_request_id: AtomicU64::new(1),
            pending_tcp_connects: Mutex::new(HashMap::new()),
            pending_recording_files: Mutex::new(HashMap::new()),
            pending_recording_deletes: Mutex::new(HashMap::new()),
            pending_smtp_connects: Mutex::new(HashMap::new()),
            start_time: Instant::now(),
            requests_processed: AtomicU64::new(0),
            requests_failed: AtomicU64::new(0),
            shutdown: AtomicBool::new(false),
            server_handle,
            acme_resolver: OnceLock::new(),
            cert_expiry: OnceLock::new(),
            tls_cert_tx: Mutex::new(Some(tls_cert_tx)),
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
            tls_cert_rx,
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

        // Create response channel
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self
                .inner
                .pending_tcp_connects
                .lock()
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
            session_token,
        };

        if let Err(e) = self.inner.channel.send(&msg) {
            // Remove pending request on send error
            self.inner
                .pending_tcp_connects
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&request_id);
            return Err(format!("Failed to send TcpConnectRequest: {}", e));
        }

        // Wait for response with timeout
        match tokio::time::timeout(Duration::from_secs(30), rx).await {
            Ok(Ok(result)) => {
                if result.success {
                    self.inner.broker_latency.record(started_at.elapsed());
                }
                Ok(result)
            }
            Ok(Err(_)) => {
                // Channel dropped (shouldn't happen)
                Err("Response channel dropped".to_string())
            }
            Err(_) => {
                // Timeout
                self.inner
                    .pending_tcp_connects
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&request_id);
                Err("TCP connect request timeout".to_string())
            }
        }
    }

    /// Request the supervisor to broker a TCP connection to the
    /// configured SMTP relay (Issue #10) and pass the connected FD
    /// back to vauban-web via SCM_RIGHTS.
    ///
    /// The supervisor enforces:
    ///   * `target_service = Service::Web` is whitelisted only when
    ///     `[mailer]` is enabled in the supervisor config;
    ///   * `(host, port)` MUST exactly match the supervisor's
    ///     `mailer.smtp_host` / `mailer.smtp_port` (SSRF guard).
    ///
    /// On success, returns a non-blocking `tokio::net::TcpStream` ready
    /// for `STARTTLS` / SMTP exchange. The stream's lifetime is owned
    /// by the caller (typically the dispatcher task).
    ///
    /// `session_token` is sent verbatim on the wire for protocol
    /// uniformity with the proxy paths but is NOT verified by the
    /// supervisor for `target_service = Web` (see the supervisor's
    /// `handle_tcp_connect_request` for the rationale). Callers should
    /// pass an empty `Vec` here.
    pub async fn request_smtp_connect(
        &self,
        session_id: &str,
        host: &str,
        port: u16,
        session_token: Vec<u8>,
        timeout: Duration,
    ) -> Result<SmtpConnectResult, String> {
        let request_id = self.inner.next_request_id.fetch_add(1, Ordering::SeqCst);

        debug!(
            request_id,
            session_id = %session_id,
            host = %host,
            port,
            "Requesting SMTP broker from supervisor"
        );

        // Same rationale as `request_tcp_connect`: only successful
        // SMTP broker round-trips feed the dashboard tracker.
        let started_at = Instant::now();

        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self
                .inner
                .pending_smtp_connects
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            pending.insert(request_id, PendingSmtpConnect { response_tx: tx });
        }

        let msg = Message::TcpConnectRequest {
            request_id,
            session_id: session_id.to_string(),
            host: host.to_string(),
            port,
            target_service: Service::Web,
            session_token,
        };

        if let Err(e) = self.inner.channel.send(&msg) {
            self.inner
                .pending_smtp_connects
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&request_id);
            return Err(format!("Failed to send SMTP TcpConnectRequest: {}", e));
        }

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(result)) => {
                if result.success {
                    self.inner.broker_latency.record(started_at.elapsed());
                }
                Ok(result)
            }
            Ok(Err(_)) => Err("SMTP broker response channel dropped".to_string()),
            Err(_) => {
                self.inner
                    .pending_smtp_connects
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&request_id);
                Err("SMTP broker request timeout".to_string())
            }
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
        {
            let mut pending = self
                .inner
                .pending_recording_files
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            pending.insert(request_id, PendingRecordingFile { response_tx: tx });
        }

        let msg = Message::RecordingFileRequest {
            request_id,
            session_id: session_id.to_string(),
            relative_path: relative_path.to_string(),
            read_only: true,
        };

        if let Err(e) = self.inner.channel.send(&msg) {
            self.inner
                .pending_recording_files
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&request_id);
            return Err(format!("Failed to send RecordingFileRequest: {}", e));
        }

        match tokio::time::timeout(Duration::from_secs(10), rx).await {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(_)) => Err("Response channel dropped".to_string()),
            Err(_) => {
                self.inner
                    .pending_recording_files
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&request_id);
                Err("Recording file request timeout".to_string())
            }
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
        {
            let mut pending = self
                .inner
                .pending_recording_deletes
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            pending.insert(request_id, PendingRecordingDelete { response_tx: tx });
        }

        let msg = Message::RecordingDeleteRequest {
            request_id,
            session_id: session_id.to_string(),
            relative_path: relative_path.to_string(),
        };

        if let Err(e) = self.inner.channel.send(&msg) {
            self.inner
                .pending_recording_deletes
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&request_id);
            return Err(format!("Failed to send RecordingDeleteRequest: {}", e));
        }

        match tokio::time::timeout(Duration::from_secs(30), rx).await {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(_)) => Err("Response channel dropped".to_string()),
            Err(_) => {
                self.inner
                    .pending_recording_deletes
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&request_id);
                Err("Recording delete request timeout".to_string())
            }
        }
    }

    /// Get a reference to the shared inner state (for statistics).
    pub fn inner(&self) -> &Arc<SupervisorClientInner> {
        &self.inner
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

/// Receive a SCM_RIGHTS-passed file descriptor from the supervisor and
/// materialise it as a non-blocking `tokio::net::TcpStream`.
///
/// Used by the SMTP broker path (Issue #10). The supervisor performs
/// the `connect()` and ships the connected FD to vauban-web via
/// `SCM_RIGHTS`. We:
///   1. Receive an `OwnedFd` from the AF_UNIX socket-pair dedicated to
///      FD passing.
///   2. Hand-build a `std::net::TcpStream` from the raw FD (taking
///      ownership; the supervisor's copy is closed on its side after
///      `sendmsg`).
///   3. Switch the socket to non-blocking mode (mandatory for tokio).
///   4. Wrap it in `tokio::net::TcpStream::from_std`.
fn recv_smtp_stream(
    fd_passing_socket: Option<RawFd>,
    request_id: u64,
) -> Result<tokio::net::TcpStream, String> {
    let fd_socket = fd_passing_socket.ok_or_else(|| {
        format!(
            "request_id={}: no fd_passing socket configured (cannot \
             recv_fd for SMTP broker)",
            request_id
        )
    })?;

    let owned_fd = recv_fd(fd_socket)
        .map_err(|e| format!("request_id={}: recv_fd failed: {}", request_id, e))?;

    let raw_fd = owned_fd.into_raw_fd();
    // SAFETY: `raw_fd` was just received via SCM_RIGHTS from the
    // supervisor and represents a fully owned, connected TCP socket.
    // We take ownership and `from_std` will close it on drop.
    let std_stream = unsafe { std::net::TcpStream::from_raw_fd(raw_fd) };
    std_stream
        .set_nonblocking(true)
        .map_err(|e| format!("request_id={}: set_nonblocking failed: {}", request_id, e))?;
    tokio::net::TcpStream::from_std(std_stream).map_err(|e| {
        format!(
            "request_id={}: TcpStream::from_std failed: {}",
            request_id, e
        )
    })
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

                // Mailer broker (Issue #10) FIRST: those request_ids were
                // registered via `request_smtp_connect` and the supervisor
                // sends the connected FD to vauban-web via SCM_RIGHTS,
                // unlike the proxy path where the FD goes to proxy_ssh /
                // proxy_rdp directly.
                let smtp_pending = inner
                    .pending_smtp_connects
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&request_id);
                if let Some(smtp_pending) = smtp_pending {
                    let stream = if success {
                        match recv_smtp_stream(inner.fd_passing_socket, request_id) {
                            Ok(s) => Some(s),
                            Err(e) => {
                                warn!(
                                    request_id,
                                    session_id = %session_id,
                                    error = %e,
                                    "Failed to materialise SMTP stream from FD"
                                );
                                None
                            }
                        }
                    } else {
                        None
                    };
                    let materialised_ok = stream.is_some();
                    let result = SmtpConnectResult {
                        success: success && materialised_ok,
                        error: if !materialised_ok && success {
                            Some("recv_fd / TcpStream materialisation failed".to_string())
                        } else {
                            error
                        },
                        stream,
                    };
                    let _ = smtp_pending.response_tx.send(result);
                    continue;
                }

                let pending = inner
                    .pending_tcp_connects
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&request_id);
                if let Some(pending) = pending {
                    let result = TcpConnectResult { success, error };
                    let _ = pending.response_tx.send(result);
                } else {
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

                let pending = inner
                    .pending_recording_files
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&request_id);
                if let Some(pending) = pending {
                    let result = RecordingFileResult {
                        success: success && file.is_some(),
                        error: if file.is_none() && success {
                            Some("recv_fd failed".to_string())
                        } else {
                            error
                        },
                        file,
                    };
                    let _ = pending.response_tx.send(result);
                } else {
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

                let pending = inner
                    .pending_recording_deletes
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&request_id);
                if let Some(pending) = pending {
                    let result = RecordingDeleteResult {
                        success,
                        bytes_freed,
                        error,
                    };
                    let _ = pending.response_tx.send(result);
                } else {
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

    // ==================== SMTP broker (Issue #10) ====================

    #[test]
    fn test_smtp_connect_result_failure_has_no_stream() {
        let r = SmtpConnectResult {
            success: false,
            error: Some("denied".to_string()),
            stream: None,
        };
        assert!(!r.success);
        assert!(r.stream.is_none());
        assert_eq!(r.error.as_deref(), Some("denied"));
    }

    #[test]
    fn test_smtp_connect_result_debug_redacts_stream() {
        let r = SmtpConnectResult {
            success: false,
            error: None,
            stream: None,
        };
        let dbg = format!("{:?}", r);
        // No surprise leak of internals; the stream field is
        // hand-formatted by the manual Debug impl.
        assert!(dbg.contains("SmtpConnectResult"));
        assert!(dbg.contains("success: false"));
    }

    /// Pin: the IPC loop MUST consult `pending_smtp_connects` BEFORE
    /// `pending_tcp_connects` for an incoming `TcpConnectResponse`,
    /// otherwise a mailer request would race against the proxy lookup
    /// and (a) be silently dropped if the proxy map happens to also
    /// have the request_id in the future, or (b) leak the SCM_RIGHTS
    /// FD because no path consumes it.
    #[test]
    fn test_supervisor_loop_consults_smtp_pending_before_tcp_pending() {
        let source = include_str!("supervisor.rs");
        // Locate the TcpConnectResponse handler in the IPC loop.
        let handler_start = source
            .find("Ok(Message::TcpConnectResponse {")
            .expect("TcpConnectResponse handler must exist");
        let handler = &source[handler_start..];
        let smtp_idx = handler
            .find("pending_smtp_connects")
            .expect("TcpConnectResponse handler MUST consult pending_smtp_connects");
        let tcp_idx = handler
            .find("pending_tcp_connects")
            .expect("TcpConnectResponse handler MUST consult pending_tcp_connects");
        assert!(
            smtp_idx < tcp_idx,
            "pending_smtp_connects MUST be consulted BEFORE \
             pending_tcp_connects in the IPC loop. The mailer path \
             needs to consume the SCM_RIGHTS FD; routing the response \
             through the proxy path would leak the FD."
        );
    }

    /// Pin: the SMTP broker request MUST set `target_service =
    /// Service::Web`. The supervisor's whitelist is keyed by that
    /// variant; sending any other (e.g. ProxySsh) here would either
    /// hit the proxy crypto path (rejected, no key) or open a TCP
    /// connection routed to the SSH proxy, which is a serious
    /// confused-deputy bug.
    #[test]
    fn test_request_smtp_connect_uses_service_web() {
        let source = include_str!("supervisor.rs");
        let fn_start = source
            .find("pub async fn request_smtp_connect(")
            .expect("request_smtp_connect must exist");
        let fn_body = &source[fn_start..];
        let fn_end = fn_body
            .find("\n    /// ")
            .or_else(|| fn_body.find("\n    pub "))
            .unwrap_or(fn_body.len().min(4096));
        let fn_body = &fn_body[..fn_end];
        assert!(
            fn_body.contains("target_service: Service::Web"),
            "request_smtp_connect MUST set target_service: Service::Web; \
             any other variant would route the broker request to the \
             wrong supervisor branch (Issue #10 confused-deputy guard)."
        );
    }
}
