// Relax strict clippy lints in test code where unwrap/expect/panic are idiomatic
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

//! Vauban SSH Proxy Service
//!
//! Handles:
//! - SSH session proxying using russh (async)
//! - Session management for multiple concurrent connections
//! - Authorization via RBAC service
//! - Credential retrieval from Vault service
//! - Audit event logging
//!
//! This service uses Tokio as an exception to the minimalist philosophy
//! (see section 2.3 of Vauban_Privsep_Architecture) because it manages
//! continuous bidirectional streams with multiple concurrent connections.

mod error;
mod input_redactor;
mod ipc;
mod session;
mod session_manager;

use anyhow::{Context, Result};
use error::SessionError;
use ipc::{AccessRbacClient, AsyncIpcChannel};
use secrecy::SecretString;
use session::{SessionConfig, SshCredential, fetch_host_key};
use session_manager::SessionManager;
use shared::capsicum;
use shared::ipc::{IpcChannel, recv_fd};
use shared::messages::{ControlMessage, Message, ServiceStats};
use std::collections::HashMap;
use std::os::unix::io::{OwnedFd, RawFd};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, mpsc};
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

/// Service runtime state (shared across async tasks).
struct ServiceState {
    start_time: Instant,
    requests_processed: AtomicU64,
    requests_failed: AtomicU64,
    /// Number of RBAC re-checks that hit the hard timeout against
    /// vauban-access. Folded into `requests_failed` for the wire-level
    /// ServiceStats (no breaking change to the bincode layout) but
    /// surfaced separately in the local Pong log so operators can
    /// distinguish "policy denied" from "access tier is wedged".
    rbac_recheck_timeouts: AtomicU64,
    draining: AtomicBool,
    /// Flag set by ControlMessage::Shutdown to break the main loop
    /// and allow destructors to run (SecretString credentials).
    shutdown_requested: AtomicBool,
}

/// Pending TCP connections received from supervisor via FD passing.
/// Maps session_id -> pre-established TCP connection FD.
type PendingConnections = Arc<Mutex<HashMap<String, OwnedFd>>>;

/// FD passing socket for receiving TCP connections from supervisor.
/// The supervisor establishes TCP connections and passes the FDs here via SCM_RIGHTS.
struct FdPassingState {
    /// Unix socket for receiving FDs from supervisor.
    socket_fd: RawFd,
    /// Pending connections waiting to be used by SSH sessions.
    pending: PendingConnections,
}

/// Receive a file descriptor with retry and async polling.
///
/// The FD and IPC notification travel on separate channels, so there's a race condition.
/// This function polls the socket and retries until the FD arrives or timeout.
async fn receive_fd_with_retry(
    socket_fd: RawFd,
    max_retries: u32,
    delay_ms: u64,
) -> Result<OwnedFd, shared::ipc::IpcError> {
    use shared::ipc::poll_readable;

    for attempt in 0..max_retries {
        // Check if socket has data available
        match poll_readable(&[socket_fd], 0) {
            Ok(ready) if !ready.is_empty() => {
                // Socket is readable, try to receive
                return recv_fd(socket_fd);
            }
            Ok(_) => {
                // Not ready yet, wait and retry
                if attempt < max_retries - 1 {
                    tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                }
            }
            Err(e) => {
                warn!(attempt, error = %e, "poll_readable failed");
                if attempt < max_retries - 1 {
                    tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                }
            }
        }
    }

    // Final attempt without poll
    recv_fd(socket_fd)
}

impl Default for ServiceState {
    fn default() -> Self {
        Self {
            start_time: Instant::now(),
            requests_processed: AtomicU64::new(0),
            requests_failed: AtomicU64::new(0),
            rbac_recheck_timeouts: AtomicU64::new(0),
            draining: AtomicBool::new(false),
            shutdown_requested: AtomicBool::new(false),
        }
    }
}

impl ServiceState {
    fn increment_processed(&self) {
        self.requests_processed.fetch_add(1, Ordering::SeqCst);
    }

    fn increment_failed(&self) {
        self.requests_failed.fetch_add(1, Ordering::SeqCst);
    }

    fn increment_rbac_timeout(&self) {
        self.rbac_recheck_timeouts.fetch_add(1, Ordering::SeqCst);
        self.requests_failed.fetch_add(1, Ordering::SeqCst);
    }

    fn rbac_timeout_count(&self) -> u64 {
        self.rbac_recheck_timeouts.load(Ordering::SeqCst)
    }

    fn stats(&self, active_sessions: u32) -> ServiceStats {
        ServiceStats {
            uptime_secs: self.start_time.elapsed().as_secs(),
            requests_processed: self.requests_processed.load(Ordering::SeqCst),
            requests_failed: self.requests_failed.load(Ordering::SeqCst),
            active_connections: active_sessions,
            pending_requests: 0,
        }
    }
}

fn main() -> ExitCode {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    info!("vauban-proxy-ssh starting (async mode with Tokio)");

    // Build and run the Tokio runtime
    // SAFETY: Tokio runtime creation is a startup invariant - the service cannot run without it
    #[allow(clippy::expect_used)]
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to create Tokio runtime");

    match runtime.block_on(run_service()) {
        Ok(()) => {
            info!("vauban-proxy-ssh exiting normally");
            ExitCode::SUCCESS
        }
        Err(e) => {
            error!("vauban-proxy-ssh error: {:#}", e);
            ExitCode::FAILURE
        }
    }
}

async fn run_service() -> Result<()> {
    // Get IPC file descriptors from environment
    let supervisor_read_fd: RawFd = std::env::var("VAUBAN_IPC_READ")
        .unwrap_or_else(|_| "0".to_string())
        .parse()
        .context("Invalid VAUBAN_IPC_READ")?;
    let supervisor_write_fd: RawFd = std::env::var("VAUBAN_IPC_WRITE")
        .unwrap_or_else(|_| "1".to_string())
        .parse()
        .context("Invalid VAUBAN_IPC_WRITE")?;

    // Get IPC channels for web service (from environment, passed by supervisor)
    let web_read_fd: RawFd = std::env::var("VAUBAN_WEB_IPC_READ")
        .context("VAUBAN_WEB_IPC_READ not set - supervisor must provide web IPC channel")?
        .parse()
        .context("Invalid VAUBAN_WEB_IPC_READ")?;
    let web_write_fd: RawFd = std::env::var("VAUBAN_WEB_IPC_WRITE")
        .context("VAUBAN_WEB_IPC_WRITE not set - supervisor must provide web IPC channel")?
        .parse()
        .context("Invalid VAUBAN_WEB_IPC_WRITE")?;

    // Get FD passing socket for receiving TCP connections from supervisor
    // This socket is used with SCM_RIGHTS to receive pre-established TCP connections
    let fd_passing_socket: Option<RawFd> = std::env::var("VAUBAN_FD_PASSING_SOCKET")
        .ok()
        .and_then(|s| s.parse().ok());

    let recording_enabled: bool = std::env::var("VAUBAN_RECORDING_ENABLED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(false);

    let audit_fds: Option<(RawFd, RawFd)> = if recording_enabled {
        let r: Option<RawFd> = std::env::var("VAUBAN_AUDIT_IPC_READ")
            .ok()
            .and_then(|s| s.parse().ok());
        let w: Option<RawFd> = std::env::var("VAUBAN_AUDIT_IPC_WRITE")
            .ok()
            .and_then(|s| s.parse().ok());
        match (r, w) {
            (Some(r), Some(w)) => Some((r, w)),
            _ => {
                warn!("Recording enabled but VAUBAN_AUDIT_IPC_READ/WRITE not set");
                None
            }
        }
    } else {
        None
    };

    // SECURITY: Mandatory access pipe to vauban-access. Without this client
    // the proxy cannot re-verify SSH session opens, so we refuse to start
    // (fail-closed boot) rather than silently degrading to "trust whatever
    // vauban-web sent us". The supervisor wires `ProxySsh -> Access` in its
    // TOPOLOGY and exports VAUBAN_ACCESS_IPC_READ / VAUBAN_ACCESS_IPC_WRITE.
    let access_read_fd: RawFd = std::env::var("VAUBAN_ACCESS_IPC_READ")
        .context(
            "VAUBAN_ACCESS_IPC_READ not set - vauban-proxy-ssh requires an access IPC pipe \
             (refusing to start; sessions cannot be authorised without it)",
        )?
        .parse()
        .context("Invalid VAUBAN_ACCESS_IPC_READ")?;
    let access_write_fd: RawFd = std::env::var("VAUBAN_ACCESS_IPC_WRITE")
        .context(
            "VAUBAN_ACCESS_IPC_WRITE not set - vauban-proxy-ssh requires an access IPC pipe \
             (refusing to start; sessions cannot be authorised without it)",
        )?
        .parse()
        .context("Invalid VAUBAN_ACCESS_IPC_WRITE")?;

    // SAFETY: We clear environment variables immediately after reading.
    unsafe {
        std::env::remove_var("VAUBAN_IPC_READ");
        std::env::remove_var("VAUBAN_IPC_WRITE");
        std::env::remove_var("VAUBAN_WEB_IPC_READ");
        std::env::remove_var("VAUBAN_WEB_IPC_WRITE");
        std::env::remove_var("VAUBAN_FD_PASSING_SOCKET");
        std::env::remove_var("VAUBAN_RECORDING_ENABLED");
        std::env::remove_var("VAUBAN_AUDIT_IPC_READ");
        std::env::remove_var("VAUBAN_AUDIT_IPC_WRITE");
        std::env::remove_var("VAUBAN_ACCESS_IPC_READ");
        std::env::remove_var("VAUBAN_ACCESS_IPC_WRITE");
    }

    // Create IPC channels
    let supervisor_channel =
        unsafe { IpcChannel::from_raw_fds(supervisor_read_fd, supervisor_write_fd) };
    let web_channel = unsafe { IpcChannel::from_raw_fds(web_read_fd, web_write_fd) };

    info!("IPC channels established");

    // Initialize FD passing state if socket is available
    let fd_passing = fd_passing_socket.map(|fd| {
        info!("FD passing socket available (fd={})", fd);
        Arc::new(FdPassingState {
            socket_fd: fd,
            pending: Arc::new(Mutex::new(HashMap::new())),
        })
    });

    if fd_passing.is_none() {
        warn!("FD passing socket not configured - SSH connections may fail in sandbox mode");
    }

    // Create async wrappers for IPC
    let supervisor_async = AsyncIpcChannel::new(supervisor_channel)
        .context("Failed to create async supervisor channel")?;
    let web_async =
        AsyncIpcChannel::new(web_channel).context("Failed to create async web channel")?;

    // SECURITY: Initialise the Access RBAC client BEFORE entering the
    // Capsicum sandbox so that any setup-time failure terminates the
    // service (fail-closed boot). Once `process_incoming` is spawned, the
    // client is ready to multiplex concurrent CheckAccessByUuid checks.
    let access_client = AccessRbacClient::new(access_read_fd, access_write_fd)
        .context("Failed to create access IPC client (RBAC re-check pipe)")?;
    info!("Access RBAC client initialised");

    let audit_channel = audit_fds.map(|(r, w)| {
        let ch = unsafe { IpcChannel::from_raw_fds(r, w) };
        info!("Audit IPC channel opened for session recording");
        ch
    });

    info!("Resources opened, preparing to enter sandbox");

    // Collect IPC file descriptors for sandboxing (read/write pipes)
    let mut ipc_fds = vec![
        supervisor_read_fd,
        supervisor_write_fd,
        web_read_fd,
        web_write_fd,
        access_read_fd,
        access_write_fd,
    ];
    if let Some((r, w)) = audit_fds {
        ipc_fds.push(r);
        ipc_fds.push(w);
    }

    // FD passing socket needs different rights (receive-only for SCM_RIGHTS)
    let fd_receiver_fds: Option<Vec<RawFd>> = fd_passing_socket.map(|fd| vec![fd]);

    // Enter Capsicum sandbox with appropriate rights for each FD type
    capsicum::setup_service_sandbox_extended(
        &ipc_fds,
        None, // No database connection
        fd_receiver_fds.as_deref(),
    )
    .context("Failed to setup sandbox")?;

    info!("Entered Capsicum sandbox, starting main loop");

    // Initialize state and session manager
    let state = Arc::new(ServiceState::default());
    let sessions = Arc::new(SessionManager::new());

    // SECURITY: Spawn the access RBAC dispatcher. Without this task the
    // proxy would deadlock on every CheckAccessByUuid; surfacing the task's
    // exit at error level lets ops detect that the service is now unable to
    // authorise sessions (every check_access_by_uuid will hang on its
    // oneshot receiver). We do NOT panic the runtime here -- the supervisor
    // is responsible for restarting us.
    {
        let access_client_for_dispatch = Arc::clone(&access_client);
        tokio::spawn(async move {
            if let Err(e) = access_client_for_dispatch.process_incoming().await {
                error!(error = %e, "Access RBAC dispatcher exited; future SSH session opens will fail-closed on timeout");
            }
        });
        info!("Access RBAC dispatcher started");
    }

    let audit_tx: Option<mpsc::Sender<Message>> = audit_channel.map(|ch| {
        let (tx, mut rx) = mpsc::channel::<Message>(512);
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                if let Err(e) = ch.send(&msg) {
                    warn!(error = %e, "Failed to send recording frame to audit");
                    break;
                }
            }
            debug!("Audit IPC writer task exiting");
        });
        tx
    });

    // Create channel for sending SSH data back to web
    let (web_tx, web_rx) = mpsc::channel::<Message>(256);

    // Run the main event loop
    main_loop(
        supervisor_async,
        web_async,
        state,
        sessions,
        (web_tx, web_rx),
        fd_passing,
        audit_tx,
        access_client,
    )
    .await
}

#[allow(clippy::too_many_arguments)] // orchestration entry point; grouping these into a struct would obscure the wiring
async fn main_loop(
    supervisor_channel: AsyncIpcChannel,
    web_channel: AsyncIpcChannel,
    state: Arc<ServiceState>,
    sessions: Arc<SessionManager>,
    web_mpsc: (mpsc::Sender<Message>, mpsc::Receiver<Message>),
    fd_passing: Option<Arc<FdPassingState>>,
    audit_tx: Option<mpsc::Sender<Message>>,
    access_client: Arc<AccessRbacClient>,
) -> Result<()> {
    let (web_tx, mut web_rx) = web_mpsc;
    info!("Main event loop started");

    // Create a channel for spawned tasks to send IPC responses back to the main loop.
    // This allows session creation to run in the background without blocking heartbeats.
    let (response_tx, mut response_rx) = mpsc::unbounded_channel::<Message>();

    // Get pending connections reference for passing to handlers
    let pending_connections = fd_passing.as_ref().map(|fp| Arc::clone(&fp.pending));

    loop {
        // Check shutdown flag before blocking on select.
        if state.shutdown_requested.load(Ordering::SeqCst) {
            info!("Shutdown flag set, exiting main loop to run destructors");
            break;
        }

        tokio::select! {
            // Handle supervisor messages (ping/pong, drain, shutdown, TcpConnectResponse)
            result = supervisor_channel.recv() => {
                match result {
                    Ok(Message::Control(ctrl)) => {
                        handle_control_message(&supervisor_channel, &state, &sessions, ctrl).await?;
                    }
                    Ok(Message::TcpConnectResponse { session_id, success, error, .. }) => {
                        // Supervisor is notifying us about an incoming FD
                        if success {
                            if let Some(ref fp) = fd_passing {
                                // Wait for the FD to be available, then receive it via SCM_RIGHTS.
                                // The FD travels on a separate socket from the IPC message,
                                // so we need to poll until it arrives.
                                let fd_result = receive_fd_with_retry(fp.socket_fd, 10, 50).await;
                                match fd_result {
                                    Ok(fd) => {
                                        debug!(session_id = %session_id, fd = ?fd, "Received TCP connection FD from supervisor");
                                        fp.pending.lock().await.insert(session_id, fd);
                                    }
                                    Err(e) if e.to_string().contains("not available") || e.to_string().contains("Unsupported") => {
                                        debug!(session_id = %session_id, "FD passing not available on this platform, session will connect directly");
                                    }
                                    Err(e) => {
                                        error!(session_id = %session_id, error = %e, "Failed to receive FD from supervisor");
                                    }
                                }
                            } else {
                                warn!(session_id = %session_id, "TcpConnectResponse received but FD passing not configured");
                            }
                        } else {
                            warn!(session_id = %session_id, error = ?error, "TCP connection failed");
                        }
                    }
                    Ok(msg) => {
                        debug!(?msg, "Received non-control message from supervisor");
                    }
                    Err(ipc::IpcError::ConnectionClosed) => {
                        info!("Supervisor connection closed, exiting");
                        return Ok(());
                    }
                    Err(e) => {
                        error!(error = %e, "Error receiving from supervisor");
                        state.increment_failed();
                    }
                }
            }

            // Handle messages from vauban-web
            result = web_channel.recv() => {
                match result {
                    Ok(msg) => {
                        if let Err(e) = handle_web_message(
                            &response_tx,
                            Arc::clone(&state),
                            Arc::clone(&sessions),
                            web_tx.clone(),
                            msg,
                            pending_connections.clone(),
                            audit_tx.clone(),
                            Arc::clone(&access_client),
                        ).await {
                            warn!(error = %e, "Error handling web message");
                            state.increment_failed();
                        }
                    }
                    Err(ipc::IpcError::ConnectionClosed) => {
                        info!("Web connection closed");
                        // Don't exit - we can still serve existing sessions
                    }
                    Err(e) => {
                        error!(error = %e, "Error receiving from web");
                        state.increment_failed();
                    }
                }
            }

            // Forward SSH output data back to web
            Some(msg) = web_rx.recv() => {
                if let Err(e) = web_channel.send(&msg) {
                    warn!(error = %e, "Failed to send SSH data to web");
                }
            }

            // Forward IPC responses from spawned tasks to web
            Some(response) = response_rx.recv() => {
                if let Err(e) = web_channel.send(&response) {
                    warn!(error = %e, "Failed to send response to web");
                }
            }
        }
    }

    Ok(())
}

async fn handle_control_message(
    channel: &AsyncIpcChannel,
    state: &ServiceState,
    sessions: &SessionManager,
    ctrl: ControlMessage,
) -> Result<()> {
    match ctrl {
        ControlMessage::Ping { seq } => {
            let stats = state.stats(sessions.active_count());
            let pong = Message::Control(ControlMessage::Pong { seq, stats });
            channel.send(&pong)?;
            debug!(seq = seq, "Responded to ping");
        }
        ControlMessage::Drain => {
            let active = sessions.active_count();
            info!(active_sessions = active, "Drain requested");
            state.draining.store(true, Ordering::SeqCst);
            let response = Message::Control(ControlMessage::DrainComplete {
                pending_requests: active,
            });
            channel.send(&response)?;
        }
        ControlMessage::Shutdown => {
            info!("Shutdown requested, setting graceful shutdown flag");
            // Set flag instead of exit(0) so the main loop breaks
            // and destructors run (SecretString credentials, session state).
            state.shutdown_requested.store(true, Ordering::SeqCst);
        }
        _ => {
            debug!(?ctrl, "Ignoring control message");
        }
    }
    Ok(())
}

/// Channel for sending IPC responses from spawned tasks.
/// This avoids needing to share the AsyncIpcChannel across tasks.
type ResponseSender = mpsc::UnboundedSender<Message>;

#[allow(clippy::too_many_arguments)] // dispatch handler; arguments map 1:1 onto IPC dependencies and grouping would only add indirection
async fn handle_web_message(
    response_tx: &ResponseSender,
    state: Arc<ServiceState>,
    sessions: Arc<SessionManager>,
    web_tx: mpsc::Sender<Message>,
    msg: Message,
    pending_connections: Option<PendingConnections>,
    audit_tx: Option<mpsc::Sender<Message>>,
    access_client: Arc<AccessRbacClient>,
) -> Result<()> {
    match msg {
        Message::SshSessionOpen {
            request_id,
            session_id,
            user_id,
            asset_id,
            asset_host,
            asset_port,
            username,
            terminal_cols,
            terminal_rows,
            auth_type,
            password,
            private_key,
            passphrase,
            expected_host_key,
        } => {
            debug!(
                session_id = %session_id,
                user_id = %user_id,
                asset_host = %asset_host,
                auth_type = %auth_type,
                "SSH session open request"
            );

            // Check if we're draining
            if state.draining.load(Ordering::SeqCst) {
                let response = Message::SshSessionOpened {
                    request_id,
                    session_id,
                    success: false,
                    error: Some("Service is draining, not accepting new sessions".to_string()),
                };
                let _ = response_tx.send(response);
                return Ok(());
            }

            // Build credential from received authentication data
            // TODO: In production, credentials should come from Vault
            // Convert SensitiveString credentials (from IPC transport) into
            // SecretString.
            let credential = match auth_type.as_str() {
                "private_key" => {
                    if let Some(key) = private_key {
                        SshCredential::PrivateKey {
                            key_pem: SecretString::from(key.into_inner()),
                            passphrase: passphrase.map(|p| SecretString::from(p.into_inner())),
                        }
                    } else {
                        let response = Message::SshSessionOpened {
                            request_id,
                            session_id,
                            success: false,
                            error: Some(
                                "Private key authentication selected but no key provided"
                                    .to_string(),
                            ),
                        };
                        let _ = response_tx.send(response);
                        return Ok(());
                    }
                }
                _ => {
                    // Default to password authentication
                    if let Some(pwd) = password {
                        SshCredential::Password(SecretString::from(pwd.into_inner()))
                    } else {
                        let response = Message::SshSessionOpened {
                            request_id,
                            session_id,
                            success: false,
                            error: Some(
                                "Password authentication selected but no password provided"
                                    .to_string(),
                            ),
                        };
                        let _ = response_tx.send(response);
                        return Ok(());
                    }
                }
            };

            // Check if we have a pre-established TCP connection for this session
            // (provided by the supervisor via FD passing for sandboxed operation)
            let preconnected_fd = if let Some(ref pending) = pending_connections {
                pending.lock().await.remove(&session_id)
            } else {
                None
            };

            if preconnected_fd.is_some() {
                debug!(session_id = %session_id, "Using pre-established TCP connection from supervisor");
            }

            // Create session configuration
            let config = SessionConfig {
                session_id: session_id.clone(),
                user_id,
                asset_id,
                host: asset_host,
                port: asset_port,
                username,
                terminal_cols,
                terminal_rows,
                credential,
                preconnected_fd,
                expected_host_key,
            };

            // Spawn session creation in a separate task to avoid blocking the main loop.
            // This allows the service to continue responding to heartbeats during
            // potentially slow SSH connections AND during the defense-in-depth
            // RBAC re-check (see below). If we did the re-check inline, any IPC
            // hang against vauban-access would freeze the main loop, miss
            // supervisor heartbeats, and trigger an unresponsive-restart.
            let sessions_clone = Arc::clone(&sessions);
            let state_clone = Arc::clone(&state);
            let response_tx_clone = response_tx.clone();
            let access_client_clone = Arc::clone(&access_client);
            let rbac_user = config.user_id.clone();
            let rbac_asset = config.asset_id.clone();

            tokio::spawn(async move {
                // SECURITY: Defense-in-depth RBAC re-check.
                //
                // vauban-web has already evaluated authorisation before emitting
                // SshSessionOpen, but we cannot blindly trust that gate -- a
                // compromised or buggy web tier must not be able to single-
                // handedly authorise an outbound SSH connection. Re-verify with
                // vauban-access (the canonical policy holder) before doing
                // anything credential-related.
                //
                // Hard timeout: if vauban-access does not respond within
                // RBAC_RECHECK_TIMEOUT we fail closed. Without this guard a
                // wedged access tier (dead pipe, saturated DB pool, code
                // panic) would leave this task pending forever, leak the
                // session slot, and never emit a SshSessionOpened response
                // to the client.
                //
                // Fail-closed: any error path -- explicit policy denial,
                // backend Error response, IPC transport failure, timeout --
                // collapses to a generic "denied" SshSessionOpened reply.
                // We never expose the distinction to the client because
                // doing so would let a probe distinguish "asset exists but
                // I can't reach it" from "asset doesn't exist"
                // (information disclosure).
                // Bumped from 5s to 10s after first soak: handle_check_access_by_uuid
                // does 3 sequential DB queries on a current_thread runtime in
                // vauban-access; under DB load the median is ~50ms but a p99
                // tail of 1-2s is realistic. 10s leaves us comfortably below
                // the supervisor's ~20s heartbeat threshold while still
                // failing closed long before any user-visible spinner stalls
                // forever. If rbac_recheck_timeouts ever climbs in prod,
                // scale up vauban-access (multi-thread runtime / connection
                // pool) rather than nudging this further up.
                const RBAC_RECHECK_TIMEOUT: Duration = Duration::from_secs(10);
                let rbac_outcome = timeout(
                    RBAC_RECHECK_TIMEOUT,
                    access_client_clone.check_access_by_uuid(&rbac_user, &rbac_asset, "ssh"),
                )
                .await;

                let allowed = match rbac_outcome {
                    Ok(Ok(true)) => {
                        debug!(
                            session_id = %session_id, user_id = %rbac_user, asset_id = %rbac_asset,
                            "RBAC re-check granted SSH session"
                        );
                        true
                    }
                    Ok(Ok(false)) => {
                        warn!(
                            session_id = %session_id, user_id = %rbac_user, asset_id = %rbac_asset,
                            "RBAC re-check denied SSH session (policy)"
                        );
                        false
                    }
                    Ok(Err(e)) => {
                        error!(
                            session_id = %session_id, user_id = %rbac_user, asset_id = %rbac_asset,
                            error = %e,
                            "RBAC re-check IPC error - denying fail-closed"
                        );
                        false
                    }
                    Err(_elapsed) => {
                        state_clone.increment_rbac_timeout();
                        error!(
                            session_id = %session_id, user_id = %rbac_user, asset_id = %rbac_asset,
                            timeout_secs = RBAC_RECHECK_TIMEOUT.as_secs(),
                            cumulative_rbac_timeouts = state_clone.rbac_timeout_count(),
                            "RBAC re-check timed out - denying fail-closed (vauban-access \
                             may be wedged or saturated; check its peer attachment count \
                             and DB pool health)"
                        );
                        // Already incremented requests_failed inside
                        // increment_rbac_timeout(); skip the generic
                        // increment_failed() in the !allowed branch below.
                        let _ = response_tx_clone.send(Message::SshSessionOpened {
                            request_id,
                            session_id,
                            success: false,
                            error: Some("Access denied".to_string()),
                        });
                        return;
                    }
                };

                if !allowed {
                    state_clone.increment_failed();
                    let _ = response_tx_clone.send(Message::SshSessionOpened {
                        request_id,
                        session_id,
                        success: false,
                        error: Some("Access denied".to_string()),
                    });
                    return;
                }

                match sessions_clone
                    .create_session(config, web_tx, audit_tx)
                    .await
                {
                    Ok(_) => {
                        state_clone.increment_processed();
                        let response = Message::SshSessionOpened {
                            request_id,
                            session_id,
                            success: true,
                            error: None,
                        };
                        let _ = response_tx_clone.send(response);
                    }
                    Err(e) => {
                        state_clone.increment_failed();
                        let response = Message::SshSessionOpened {
                            request_id,
                            session_id,
                            success: false,
                            error: Some(e.to_string()),
                        };
                        let _ = response_tx_clone.send(response);
                    }
                }
            });
        }

        Message::SshData { session_id, data } => {
            if let Err(e) = sessions.send_data(&session_id, data).await {
                match e {
                    SessionError::SessionNotFound(_) => {
                        debug!(session_id = %session_id, "Data for unknown session");
                    }
                    _ => {
                        warn!(session_id = %session_id, error = %e, "Failed to send data to session");
                    }
                }
            }
        }

        Message::SshResize {
            session_id,
            cols,
            rows,
        } => {
            if let Err(e) = sessions.resize(&session_id, cols, rows).await {
                warn!(session_id = %session_id, error = %e, "Failed to resize session");
            }
        }

        Message::SshSessionClose { session_id } => {
            info!(session_id = %session_id, "Session close request");
            if let Err(e) = sessions.close_session(&session_id).await {
                warn!(session_id = %session_id, error = %e, "Failed to close session");
            }
        }

        // SSH host key fetch request
        Message::SshFetchHostKey {
            request_id,
            asset_host,
            asset_port,
        } => {
            info!(
                asset_host = %asset_host,
                asset_port = asset_port,
                "SSH host key fetch request"
            );

            // Check if we have a pre-established TCP connection for this fetch
            // Use a synthetic session_id for the fetch operation
            let fetch_session_id = format!("fetch-hostkey-{}", request_id);
            let preconnected_fd = if let Some(ref pending) = pending_connections {
                pending.lock().await.remove(&fetch_session_id)
            } else {
                None
            };

            let response_tx_clone = response_tx.clone();
            let host = asset_host.clone();
            let port = asset_port;

            tokio::spawn(async move {
                let result: Result<(String, String), SessionError> =
                    fetch_host_key(&host, port, preconnected_fd).await;
                let response = match result {
                    Ok((host_key, fingerprint)) => Message::SshHostKeyResult {
                        request_id,
                        success: true,
                        host_key: Some(host_key),
                        key_fingerprint: Some(fingerprint),
                        error: None,
                    },
                    Err(e) => Message::SshHostKeyResult {
                        request_id,
                        success: false,
                        host_key: None,
                        key_fingerprint: None,
                        error: Some(e.to_string()),
                    },
                };
                let _ = response_tx_clone.send(response);
            });
        }

        // Handle responses from other services (RBAC, Vault, ...)
        Message::RbacResponse { request_id, result } => {
            debug!(
                request_id = request_id,
                allowed = result.allowed,
                "RBAC response received"
            );
            state.increment_processed();
        }

        // SECURITY: a legacy "vault credential response" arm used to live
        // here that logged the response without enforcing any policy. The
        // corresponding IPC verb has been removed from `shared::messages`
        // (post-MFA security pass) because its sibling "get credential by
        // id" verb returned `credential: None` silently and could have been
        // misinterpreted as "no credential needed -> allow". When credential
        // retrieval is reintroduced it must go through the encrypted-transit
        // verbs (`VaultEncrypt` / `VaultDecrypt`).
        _ => {
            debug!(?msg, "Ignoring unexpected message type");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_state_default() {
        let state = ServiceState::default();
        assert_eq!(state.requests_processed.load(Ordering::SeqCst), 0);
        assert!(!state.draining.load(Ordering::SeqCst));
    }

    #[test]
    fn test_service_state_increment() {
        let state = ServiceState::default();
        state.increment_processed();
        state.increment_processed();
        state.increment_failed();
        assert_eq!(state.requests_processed.load(Ordering::SeqCst), 2);
        assert_eq!(state.requests_failed.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_service_state_stats() {
        let state = ServiceState::default();
        state.increment_processed();
        let stats = state.stats(5);
        assert_eq!(stats.requests_processed, 1);
        assert_eq!(stats.active_connections, 5);
    }

    #[tokio::test]
    async fn test_handle_control_ping() {
        let (supervisor, service) = IpcChannel::pair().unwrap();
        let service_async = AsyncIpcChannel::new(service).unwrap();
        let state = ServiceState::default();
        let sessions = SessionManager::new();

        handle_control_message(
            &service_async,
            &state,
            &sessions,
            ControlMessage::Ping { seq: 42 },
        )
        .await
        .unwrap();

        let response: Message = supervisor.recv().unwrap();
        if let Message::Control(ControlMessage::Pong { seq, stats }) = response {
            assert_eq!(seq, 42);
            assert_eq!(stats.active_connections, 0);
        } else {
            panic!("Expected Pong");
        }
    }

    #[tokio::test]
    async fn test_handle_control_drain() {
        let (supervisor, service) = IpcChannel::pair().unwrap();
        let service_async = AsyncIpcChannel::new(service).unwrap();
        let state = ServiceState::default();
        let sessions = SessionManager::new();

        handle_control_message(&service_async, &state, &sessions, ControlMessage::Drain)
            .await
            .unwrap();

        assert!(state.draining.load(Ordering::SeqCst));

        let response: Message = supervisor.recv().unwrap();
        if let Message::Control(ControlMessage::DrainComplete { pending_requests }) = response {
            assert_eq!(pending_requests, 0);
        } else {
            panic!("Expected DrainComplete");
        }
    }

    // ==================== Structural Regression Tests ====================

    /// Helper: Extract production code (before #[cfg(test)]).
    fn prod_source() -> &'static str {
        let full = include_str!("main.rs");
        if let Some(idx) = full.find("#[cfg(test)]") {
            &full[..idx]
        } else {
            full
        }
    }

    #[test]
    fn test_no_process_exit_in_production_code() {
        let source = prod_source();
        assert!(
            !source.contains("process::exit"),
            "vauban-proxy-ssh must not call process::exit() in production code"
        );
    }

    #[test]
    fn test_has_shutdown_requested_flag() {
        let source = prod_source();
        assert!(
            source.contains("shutdown_requested"),
            "ServiceState must have a shutdown_requested flag"
        );
    }

    #[test]
    fn test_main_loop_checks_shutdown_flag() {
        let source = prod_source();
        // proxy-ssh uses tokio::select! in the main loop
        let loop_start = source.find("loop {").expect("main loop must exist");
        let loop_source = &source[loop_start..];
        assert!(
            loop_source.contains("shutdown_requested"),
            "main loop must check shutdown_requested flag"
        );
    }

    #[test]
    fn test_handle_control_sets_shutdown_flag() {
        let source = prod_source();
        let handle_start = source
            .find("fn handle_control_message")
            .expect("handle_control_message must exist");
        let handle_source = &source[handle_start..];
        assert!(
            handle_source.contains("shutdown_requested.store(true"),
            "handle_control_message must set shutdown_requested on Shutdown"
        );
    }

    #[test]
    fn test_shutdown_flag_is_atomic_bool() {
        let source = prod_source();
        // proxy-ssh uses AtomicBool for thread-safe access from async tasks
        assert!(
            source.contains("shutdown_requested: AtomicBool"),
            "shutdown_requested must be AtomicBool for async safety"
        );
    }

    // ==================== SSH Recording Structural Tests ====================

    #[test]
    fn test_ssh_recording_env_var_read() {
        let source = prod_source();
        assert!(
            source.contains("VAUBAN_RECORDING_ENABLED"),
            "proxy-ssh must read VAUBAN_RECORDING_ENABLED"
        );
        assert!(
            source.contains("VAUBAN_AUDIT_IPC_READ"),
            "proxy-ssh must read VAUBAN_AUDIT_IPC_READ"
        );
        assert!(
            source.contains("VAUBAN_AUDIT_IPC_WRITE"),
            "proxy-ssh must read VAUBAN_AUDIT_IPC_WRITE"
        );
    }

    #[test]
    fn test_ssh_recording_env_vars_cleaned() {
        let source = prod_source();
        assert!(
            source.contains("remove_var(\"VAUBAN_RECORDING_ENABLED\")"),
            "proxy-ssh must clean VAUBAN_RECORDING_ENABLED"
        );
        assert!(
            source.contains("remove_var(\"VAUBAN_AUDIT_IPC_READ\")"),
            "proxy-ssh must clean VAUBAN_AUDIT_IPC_READ"
        );
        assert!(
            source.contains("remove_var(\"VAUBAN_AUDIT_IPC_WRITE\")"),
            "proxy-ssh must clean VAUBAN_AUDIT_IPC_WRITE"
        );
    }

    #[test]
    fn test_ssh_recording_audit_tx_passed_to_main_loop() {
        let source = prod_source();
        let main_loop = source.find("fn main_loop").expect("main_loop must exist");
        let main_loop_source = &source[main_loop..];
        assert!(
            main_loop_source.contains("audit_tx"),
            "main_loop must receive audit_tx parameter"
        );
    }

    #[test]
    fn test_ssh_recording_audit_fds_in_sandbox() {
        let source = prod_source();
        assert!(
            source.contains("if let Some((r, w)) = audit_fds"),
            "Audit FDs must be added to sandbox ipc_fds"
        );
    }

    // ==================== RBAC re-check structural tests ====================
    //
    // SECURITY: vauban-proxy-ssh MUST defense-in-depth-verify every
    // SshSessionOpen against vauban-access before opening the upstream SSH
    // connection. These tests are anti-regression guards: they fail loudly
    // if any future change re-introduces the legacy "trust whatever
    // vauban-web sent" behaviour, ensuring the bypass identified in the
    // post-MFA security audit cannot silently come back.

    #[test]
    fn test_proxy_ssh_initialises_access_rbac_client() {
        let source = prod_source();
        assert!(
            source.contains("AccessRbacClient::new"),
            "proxy-ssh must construct an AccessRbacClient at startup"
        );
        assert!(
            source.contains("VAUBAN_ACCESS_IPC_READ")
                && source.contains("VAUBAN_ACCESS_IPC_WRITE"),
            "proxy-ssh must read access IPC fds from supervisor env vars"
        );
    }

    #[test]
    fn test_proxy_ssh_access_env_fail_closed_boot() {
        let source = prod_source();
        assert!(
            source.contains("VAUBAN_ACCESS_IPC_READ not set"),
            "proxy-ssh boot must fail with a clear error if the access IPC \
             read fd is not provided (fail-closed boot, no degraded mode)"
        );
        assert!(
            source.contains("VAUBAN_ACCESS_IPC_WRITE not set"),
            "proxy-ssh boot must fail with a clear error if the access IPC \
             write fd is not provided (fail-closed boot, no degraded mode)"
        );
    }

    #[test]
    fn test_proxy_ssh_access_env_vars_cleaned() {
        let source = prod_source();
        assert!(
            source.contains("remove_var(\"VAUBAN_ACCESS_IPC_READ\")"),
            "proxy-ssh must clean VAUBAN_ACCESS_IPC_READ from env after read"
        );
        assert!(
            source.contains("remove_var(\"VAUBAN_ACCESS_IPC_WRITE\")"),
            "proxy-ssh must clean VAUBAN_ACCESS_IPC_WRITE from env after read"
        );
    }

    #[test]
    fn test_proxy_ssh_access_fds_in_sandbox() {
        let source = prod_source();
        assert!(
            source.contains("access_read_fd") && source.contains("access_write_fd"),
            "Access RBAC FDs must be retained inside the Capsicum ipc_fds set"
        );
    }

    #[test]
    fn test_proxy_ssh_access_dispatcher_spawned() {
        let source = prod_source();
        assert!(
            source.contains(".process_incoming()"),
            "Access RBAC client dispatcher must be spawned (process_incoming) \
             so concurrent CheckAccessByUuid responses can be demultiplexed"
        );
    }

    #[test]
    fn test_proxy_ssh_session_open_calls_rbac_recheck() {
        let source = prod_source();
        // The whole-file scope is fine here: there is only one call site
        // for check_access_by_uuid in production code (the SshSessionOpen
        // handler). If a future refactor ever moves it elsewhere, this
        // assertion plus the dispatcher-spawn one (above) still guarantee
        // that the call exists somewhere reachable from main_loop.
        assert!(
            source.contains(".check_access_by_uuid(&rbac_user, &rbac_asset, \"ssh\")"),
            "SshSessionOpen handler MUST call \
             check_access_by_uuid(&rbac_user, &rbac_asset, \"ssh\") inside \
             the spawned task (defense-in-depth RBAC re-check); see security \
             audit finding #6"
        );
        // Policy-deny, IPC-error, and timeout branches must ALL collapse
        // to the same generic message so that probing cannot distinguish
        // "user lacks ssh on this asset" from "RBAC service is down" or
        // "RBAC service is hung". One literal in the spawn body covers
        // every fail-closed path, but we still want at least one
        // occurrence reachable from this handler.
        let access_denied_count = source.matches("\"Access denied\"").count();
        assert!(
            access_denied_count >= 1,
            "Expected at least 1 occurrence of the generic \"Access denied\" \
             fail-closed reply in production code, found {}",
            access_denied_count
        );
    }

    #[test]
    fn test_proxy_ssh_rbac_recheck_runs_inside_spawn() {
        // SECURITY / LIVENESS: the RBAC re-check MUST live inside the
        // `tokio::spawn` block that drives create_session, NOT inline in
        // the select! arm. If it were inline, an unresponsive vauban-access
        // (dead pipe, saturated DB pool, code panic) would freeze the
        // main_loop, miss supervisor heartbeats, and trigger an
        // unresponsive-restart. That regression actually shipped once;
        // this guard prevents it from happening again.
        let source = prod_source();
        let spawn_idx = source
            .find("tokio::spawn(async move {")
            .expect("SshSessionOpen handler must spawn create_session in a task");
        let check_idx = source
            .find(".check_access_by_uuid(&rbac_user, &rbac_asset, \"ssh\")")
            .expect("RBAC re-check call site must exist");
        assert!(
            check_idx > spawn_idx,
            "RBAC re-check MUST run inside the tokio::spawn body (after the \
             `tokio::spawn(async move {{` line) so that a slow/wedged \
             vauban-access cannot block the main loop and trigger a \
             supervisor unresponsive-restart"
        );
    }

    #[test]
    fn test_proxy_ssh_rbac_recheck_has_hard_timeout() {
        // SECURITY / LIVENESS: without a timeout, a hung vauban-access
        // would leave the spawned task pending forever, leaking the
        // session slot and never returning a SshSessionOpened response
        // to the client (front-end spinner forever). Enforce a hard
        // bound + fail-closed.
        let source = prod_source();
        assert!(
            source.contains("RBAC_RECHECK_TIMEOUT")
                && source.contains("Duration::from_secs(10)"),
            "RBAC re-check MUST be wrapped in a hard timeout \
             (RBAC_RECHECK_TIMEOUT = Duration::from_secs(10)) with fail-closed \
             on Elapsed; see post-incident hardening note"
        );
        assert!(
            source.contains("rbac_recheck_timeouts") && source.contains("increment_rbac_timeout"),
            "RBAC re-check timeouts MUST be counted in a dedicated atomic so \
             operators can distinguish 'access wedged' from 'policy denied' \
             without re-grepping logs; see ServiceState::rbac_recheck_timeouts"
        );
        assert!(
            source.contains("RBAC re-check timed out - denying fail-closed"),
            "RBAC re-check timeout branch MUST log explicitly and fall through \
             to the generic Access-denied reply (fail-closed)"
        );
    }

    #[test]
    fn test_proxy_ssh_session_open_no_legacy_rbac_todo() {
        let source = prod_source();
        // The previous fail-open placeholder was a TODO comment that read
        // `Check RBAC authorization`. If anyone re-introduces that pattern
        // (bypass via "we'll do it later"), this test must fail.
        assert!(
            !source.contains("TODO: Check RBAC authorization"),
            "Legacy 'TODO: Check RBAC authorization' placeholder must NOT \
             reappear in proxy-ssh main.rs (bypass risk: see security audit \
             finding #6 re-opening if removed)"
        );
    }
}
