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
mod vault;

use anyhow::{Context, Result};
use error::SessionError;
use ipc::AsyncIpcChannel;
use session::{SessionConfig, SshCredential, fetch_host_key};
use session_manager::{RecordingDropHook, SessionManager};
use shared::access_guard::{AccessGuard, AccessGuardMetrics, AccessGuardWiring, PROTOCOL_SSH};
use shared::ipc::{IpcChannel, recv_fd};
use shared::messages::{ControlMessage, Message, ServiceStats};
use shared::sandbox as capsicum;
use shared::session_token::proxy_gate as session_token_gate;
use std::collections::HashMap;
use std::os::unix::io::{OwnedFd, RawFd};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, error, info, warn};
use vault::{DOMAIN_CREDENTIALS, VaultDecryptClient};

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
    /// SSH recording channel try_send full drops (audit backpressure).
    recording_try_send_full: AtomicU64,
    recording_try_send_last_warn: std::sync::Mutex<Instant>,
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
///
/// SAFETY INVARIANT: this function MUST NOT make a blocking syscall on the
/// FD-passing socket under any circumstance. The socket is blocking by
/// default (`socketpair_for_fd_passing` -- `SockFlag::empty()`), so a
/// fall-through `recv_fd(socket_fd)` after all polls returned "not ready"
/// would park the calling tokio worker indefinitely on `recvmsg(2)`,
/// starving the main loop's heartbeats until the supervisor force-restarts
/// the service. When no SCM_RIGHTS FD arrives in time we fail closed with
/// a `TimedOut` error instead (same invariant as proxy-iacs; pinned by
/// `tests/no_blocking_recv_fd_test.rs`).
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

    // All retries exhausted with no SCM_RIGHTS FD ready: fail closed.
    // NEVER fall through to a blocking `recv_fd(socket_fd)` -- see the
    // safety invariant in this function's doc comment.
    Err(shared::ipc::IpcError::Io(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!(
            "ssh_proxy: receive_fd_with_retry timed out after {} attempts \
             ({} ms each); refusing to fall through to a blocking recv_fd",
            max_retries, delay_ms
        ),
    )))
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
            recording_try_send_full: AtomicU64::new(0),
            recording_try_send_last_warn: std::sync::Mutex::new(
                Instant::now() - std::time::Duration::from_secs(60),
            ),
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

    /// Read the cumulative count of RBAC re-check timeouts since boot.
    /// Surfaced via Pong logs and on the Prometheus exporter once we wire
    /// it up; kept on ServiceState rather than hidden inside AccessGuard
    /// so SREs can grab it without an extra IPC round-trip.
    #[allow(dead_code)] // observability hook; reachable from supervisor diagnostics
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
            recording_ack_timeouts: 0,
            recording_ack_dropped: 0,
            recording_try_send_full: self.recording_try_send_full.load(Ordering::SeqCst),
            recording_ack_wait_ms_max: 0,
        }
    }

    fn record_recording_try_send_full(&self, session_id: &str) {
        self.recording_try_send_full.fetch_add(1, Ordering::SeqCst);
        if let Ok(mut last) = self.recording_try_send_last_warn.lock()
            && last.elapsed() >= std::time::Duration::from_secs(10)
        {
            warn!(
                session_id = %session_id,
                "SSH recording channel full; dropping frame"
            );
            *last = Instant::now();
        }
    }
}

// Wire ServiceState into the shared AccessGuard so its grant/deny/timeout/
// ipc-error counters land on the same atomics that feed our Pong stats.
//
// SECURITY/OBSERVABILITY: each variant lands on a distinct atomic so an
// operator can tell "policy denied" from "vauban-access wedged" from "RBAC
// IPC broken" by reading /metrics or the Pong log alone, without having
// to grep raw logs.
impl AccessGuardMetrics for ServiceState {
    fn record_granted(&self) {
        // No-op on the failed counter; the success path will eventually
        // call `increment_processed` when the SSH session actually opens.
    }

    fn record_denied(&self) {
        // Policy denial: still a "request failure" from the proxy's view
        // (the client's session-open did not succeed) but we do NOT want
        // to inflate the dedicated rbac_recheck_timeouts gauge -- that
        // one signals "vauban-access health", not "user lacks rights".
        self.requests_failed.fetch_add(1, Ordering::SeqCst);
    }

    fn record_timeout(&self) {
        // Distinguished metric: a non-zero value means vauban-access is
        // wedged or saturated. Operators MUST react (scale the access
        // tier, bounce the dispatcher) rather than treating it as a
        // routine policy denial.
        self.rbac_recheck_timeouts.fetch_add(1, Ordering::SeqCst);
        self.requests_failed.fetch_add(1, Ordering::SeqCst);
    }

    fn record_ipc_error(&self) {
        // Transport-level failure (broken pipe, malformed reply). Same
        // user-visible outcome as a timeout (fail-closed denial) but
        // surfaces a different operational signal: the IPC pipe itself
        // is broken, supervisor restart will likely recreate it.
        self.requests_failed.fetch_add(1, Ordering::SeqCst);
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

    // Get the Vault IPC channel (ProxySsh -> Vault edge in the supervisor
    // topology). Used decrypt-only to materialise asset credentials from
    // the vault ciphertexts shipped in SshSessionOpen / SshPushPublicKey /
    // SshTestKeyAuth (#4: no clear-text credentials cross the web->proxy
    // IPC). Degrades cleanly when absent (in-process dev without a vault):
    // any credential decrypt then fails closed.
    let vault_fds: Option<(RawFd, RawFd)> = {
        let r: Option<RawFd> = std::env::var("VAUBAN_VAULT_IPC_READ")
            .ok()
            .and_then(|s| s.parse().ok());
        let w: Option<RawFd> = std::env::var("VAUBAN_VAULT_IPC_WRITE")
            .ok()
            .and_then(|s| s.parse().ok());
        match (r, w) {
            (Some(r), Some(w)) => Some((r, w)),
            _ => {
                warn!(
                    "Vault IPC channel not configured (VAUBAN_VAULT_IPC_READ/WRITE); \
                     credential decryption will be unavailable"
                );
                None
            }
        }
    };

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

    // SECURITY: load and CLEAR the session-token MAC key BEFORE any
    // other thread is spawned, BEFORE Capsicum closes us out of env
    // mutation, and BEFORE we accept any session-open. Without it the
    // proxy would have to fail-closed on every SshSessionOpen, which
    // is correct but useless: in production the supervisor MUST set
    // VAUBAN_SESSION_TOKEN_KEY for proxy_ssh.
    session_token_gate::init_from_env().context(
        "Failed to load VAUBAN_SESSION_TOKEN_KEY - vauban-proxy-ssh \
         requires the cryptographic session-token key (refusing to \
         start; sessions cannot be cryptographically gated without it)",
    )?;
    info!("session-token MAC key loaded (BLAKE3-keyed)");

    // SAFETY: We clear environment variables immediately after reading.
    // Note: VAUBAN_ACCESS_IPC_READ / WRITE are consumed (and removed)
    // inside AccessGuard::from_env below.
    unsafe {
        std::env::remove_var("VAUBAN_IPC_READ");
        std::env::remove_var("VAUBAN_IPC_WRITE");
        std::env::remove_var("VAUBAN_WEB_IPC_READ");
        std::env::remove_var("VAUBAN_WEB_IPC_WRITE");
        std::env::remove_var("VAUBAN_FD_PASSING_SOCKET");
        std::env::remove_var("VAUBAN_RECORDING_ENABLED");
        std::env::remove_var("VAUBAN_AUDIT_IPC_READ");
        std::env::remove_var("VAUBAN_AUDIT_IPC_WRITE");
        std::env::remove_var("VAUBAN_VAULT_IPC_READ");
        std::env::remove_var("VAUBAN_VAULT_IPC_WRITE");
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

    // Initialise state up front so AccessGuard can borrow it as its
    // metrics sink (each grant/deny/timeout/ipc-error lands on
    // ServiceState atomics; see AccessGuardMetrics impl above).
    let state = Arc::new(ServiceState::default());

    // SECURITY: Initialise the AccessGuard BEFORE entering the Capsicum
    // sandbox so that any setup-time failure (missing env, invalid fd)
    // terminates the service (fail-closed boot). The shared module
    // consumes VAUBAN_ACCESS_IPC_READ / WRITE here and removes them
    // from the env. Returned wiring exposes the FDs for Capsicum and
    // the Arc<AccessGuard> we share across per-session spawns.
    #[rustfmt::skip]
    let access_wiring: AccessGuardWiring =
        AccessGuard::from_env(PROTOCOL_SSH, Arc::clone(&state) as Arc<dyn AccessGuardMetrics>)
            .context(
                "Failed to wire AccessGuard from env (VAUBAN_ACCESS_IPC_READ / \
                 VAUBAN_ACCESS_IPC_WRITE) - vauban-proxy-ssh requires an access IPC pipe \
                 (refusing to start; sessions cannot be authorised without it)",
            )?;
    let access_guard = Arc::clone(&access_wiring.guard);
    info!("AccessGuard initialised (defense-in-depth RBAC re-check)");

    let audit_channel = audit_fds.map(|(r, w)| {
        let ch = unsafe { IpcChannel::from_raw_fds(r, w) };
        info!("Audit IPC channel opened for session recording");
        ch
    });

    // Build the decrypt-only Vault client BEFORE Capsicum so the
    // tokio AsyncFd reactor registration is not refused by the sandbox.
    // The background reader task is spawned AFTER sandbox entry (with the
    // AccessGuard dispatcher).
    let vault_client: Option<Arc<VaultDecryptClient>> = match vault_fds {
        Some((r, w)) => {
            let ch = unsafe { IpcChannel::from_raw_fds(r, w) };
            match VaultDecryptClient::new(ch) {
                Ok(client) => {
                    info!("Vault decrypt-only IPC client initialised");
                    Some(client)
                }
                Err(e) => {
                    error!(error = %e, "Failed to initialise Vault IPC client");
                    None
                }
            }
        }
        None => None,
    };

    info!("Resources opened, preparing to enter sandbox");

    // Collect IPC file descriptors for sandboxing (read/write pipes).
    // The AccessGuard FDs come from access_wiring.fds (shared module
    // owns the env parsing now).
    let mut ipc_fds = vec![
        supervisor_read_fd,
        supervisor_write_fd,
        web_read_fd,
        web_write_fd,
    ];
    ipc_fds.extend_from_slice(&access_wiring.fds);
    if let Some((r, w)) = audit_fds {
        ipc_fds.push(r);
        ipc_fds.push(w);
    }
    if let Some((r, w)) = vault_fds {
        ipc_fds.push(r);
        ipc_fds.push(w);
    }

    // FD passing socket needs different rights (receive-only for SCM_RIGHTS)
    let fd_receiver_fds: Option<Vec<RawFd>> = fd_passing_socket.map(|fd| vec![fd]);

    // Enter Capsicum sandbox with appropriate rights for each FD type
    let sealed = capsicum::setup_service_sandbox_extended(
        &ipc_fds,
        None, // No database connection
        fd_receiver_fds.as_deref(),
    )
    .context("Failed to setup sandbox")?;

    capsicum::log_main_loop_start(&sealed, "starting main loop");

    // Initialize session manager (state was created above so AccessGuard
    // could borrow it as its metrics sink).
    let sessions = Arc::new(SessionManager::new());

    // SECURITY: Spawn the AccessGuard dispatcher. Without this task,
    // every authorize() call would hit RBAC_RECHECK_TIMEOUT (10s) and
    // fail closed -- the proxy would still be safe but useless. The
    // shared module logs at error level when the dispatcher exits, so
    // operators can detect the degraded state without re-grepping logs.
    let _dispatcher_handle = access_guard.spawn_dispatcher();

    // Spawn the Vault decrypt client's background reader (routes
    // VaultDecryptResponse to awaiting callers). Spawned after sandbox
    // entry, mirroring the AccessGuard dispatcher.
    if let Some(ref vc) = vault_client {
        let vc = Arc::clone(vc);
        tokio::spawn(vc.process_incoming());
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
        sealed,
        supervisor_async,
        web_async,
        state,
        sessions,
        (web_tx, web_rx),
        fd_passing,
        audit_tx,
        access_guard,
        vault_client,
    )
    .await
}

#[allow(clippy::too_many_arguments)] // orchestration entry point; grouping these into a struct would obscure the wiring
async fn main_loop(
    _sealed: capsicum::Entered,
    supervisor_channel: AsyncIpcChannel,
    web_channel: AsyncIpcChannel,
    state: Arc<ServiceState>,
    sessions: Arc<SessionManager>,
    web_mpsc: (mpsc::Sender<Message>, mpsc::Receiver<Message>),
    fd_passing: Option<Arc<FdPassingState>>,
    audit_tx: Option<mpsc::Sender<Message>>,
    access_guard: Arc<AccessGuard>,
    vault_client: Option<Arc<VaultDecryptClient>>,
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
                            Arc::clone(&access_guard),
                            vault_client.clone(),
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

/// Materialise an [`SshCredential`] from the vault ciphertexts shipped
/// in an [`Message::SshSessionOpen`]. The plaintext is produced via the
/// decrypt-only [`VaultDecryptClient`] inside the proxy's address space
/// (#4: vauban-web never holds the clear-text secret on the hot path).
/// Fail-closed: returns `Err` if the vault is unavailable, a ciphertext
/// is missing, or the vault refuses to decrypt.
async fn build_credential_via_vault(
    vault: Option<&Arc<VaultDecryptClient>>,
    auth_type: &str,
    password_ciphertext: Option<String>,
    private_key_ciphertext: Option<String>,
    passphrase_ciphertext: Option<String>,
) -> std::result::Result<SshCredential, String> {
    let vault = vault.ok_or_else(|| "vault client not available".to_string())?;
    match auth_type {
        "ssh_key" => {
            let key_ct = private_key_ciphertext
                .ok_or_else(|| "missing private key ciphertext".to_string())?;
            let key_pem = vault.decrypt(DOMAIN_CREDENTIALS, &key_ct).await?;
            let passphrase = match passphrase_ciphertext {
                Some(ct) => Some(vault.decrypt(DOMAIN_CREDENTIALS, &ct).await?),
                None => None,
            };
            Ok(SshCredential::PrivateKey {
                key_pem,
                passphrase,
            })
        }
        _ => {
            let pwd_ct =
                password_ciphertext.ok_or_else(|| "missing password ciphertext".to_string())?;
            let pwd = vault.decrypt(DOMAIN_CREDENTIALS, &pwd_ct).await?;
            Ok(SshCredential::Password(pwd))
        }
    }
}

#[allow(clippy::too_many_arguments)] // dispatch handler; arguments map 1:1 onto IPC dependencies and grouping would only add indirection
async fn handle_web_message(
    response_tx: &ResponseSender,
    state: Arc<ServiceState>,
    sessions: Arc<SessionManager>,
    web_tx: mpsc::Sender<Message>,
    msg: Message,
    pending_connections: Option<PendingConnections>,
    audit_tx: Option<mpsc::Sender<Message>>,
    access_guard: Arc<AccessGuard>,
    vault_client: Option<Arc<VaultDecryptClient>>,
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
            password_ciphertext,
            private_key_ciphertext,
            passphrase_ciphertext,
            expected_host_key,
            session_token,
        } => {
            debug!(
                session_id = %session_id,
                user_id = %user_id,
                asset_host = %asset_host,
                auth_type = %auth_type,
                "SSH session open request"
            );

            // SECURITY: cryptographic session-token gate. Verifies the
            // BLAKE3-keyed MAC, freshness window, anti-replay nonce, and
            // field-bindings (user_uuid, asset_uuid, protocol, session_id)
            // against the token vauban-access minted. A compromised
            // vauban-web cannot piggy-back another user's session here
            // because the (user, asset) tuple inside the MAC won't match
            // the SshSessionOpen fields. Fail-closed deny on any error.
            // See docs/technical/Vauban_AccessGuard_Architecture_EN(1.0).md §3.
            if !session_token_gate::verify_proxy(
                &session_token,
                &user_id,
                &asset_id,
                "ssh",
                &session_id,
            ) {
                let response = Message::SshSessionOpened {
                    request_id,
                    session_id,
                    success: false,
                    error: Some("Access denied".to_string()),
                };
                let _ = response_tx.send(response);
                return Ok(());
            }

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

            // Cheap, no-IPC pre-validation: refuse early if the required
            // ciphertext is missing for the chosen auth type. The actual
            // decryption (Vault IPC) happens INSIDE the spawned task so a
            // slow vault cannot stall the main loop's heartbeats.
            let has_required_ciphertext = match auth_type.as_str() {
                "ssh_key" => private_key_ciphertext.is_some(),
                _ => password_ciphertext.is_some(),
            };
            if !has_required_ciphertext {
                let response = Message::SshSessionOpened {
                    request_id,
                    session_id,
                    success: false,
                    error: Some(format!(
                        "{} authentication selected but no credential ciphertext provided",
                        auth_type
                    )),
                };
                let _ = response_tx.send(response);
                return Ok(());
            }

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

            // Spawn session creation in a separate task to avoid blocking
            // the main loop. This allows the service to continue
            // responding to heartbeats during potentially slow SSH
            // connections AND during the defense-in-depth RBAC re-check
            // AND the Vault credential decryption. If we did any of these
            // inline, an IPC hang against vauban-access / vauban-vault
            // would freeze the main loop, miss supervisor heartbeats, and
            // trigger an unresponsive-restart (see
            // docs/runbooks/ipc_topology_debugging.md for the prod
            // incident this design prevents).
            let sessions_clone = Arc::clone(&sessions);
            let state_clone = Arc::clone(&state);
            let response_tx_clone = response_tx.clone();
            let access_guard_clone = Arc::clone(&access_guard);
            let vault_clone = vault_client.clone();
            let rbac_user = user_id.clone();
            let rbac_asset = asset_id.clone();
            let recording_on_full: Option<RecordingDropHook> = if audit_tx.is_some() {
                let state_for_hook = Arc::clone(&state);
                Some(Arc::new(move |session_id: &str| {
                    state_for_hook.record_recording_try_send_full(session_id);
                }))
            } else {
                None
            };

            tokio::spawn(async move {
                // SECURITY: Defense-in-depth RBAC re-check via the shared
                // AccessGuard. vauban-web has already evaluated
                // authorisation before emitting SshSessionOpen, but we
                // cannot blindly trust that gate -- a compromised or
                // buggy web tier must not be able to single-handedly
                // authorise an outbound SSH connection. AccessGuard
                // enforces RBAC_RECHECK_TIMEOUT internally, increments
                // the matching ServiceState atomic via the
                // AccessGuardMetrics impl, and never returns Result.
                //
                // Fail-closed: any non-Granted variant collapses to the
                // generic "Access denied" reply. We never expose the
                // distinction (Denied / Timeout / BackendError) to the
                // client because doing so would let a probe distinguish
                // "asset exists but I can't reach it" from "asset
                // doesn't exist" (information disclosure).
                let decision = access_guard_clone.authorize(&rbac_user, &rbac_asset).await;
                if !decision.is_granted() {
                    debug!(
                        session_id = %session_id, user_id = %rbac_user,
                        asset_id = %rbac_asset, ?decision,
                        "RBAC re-check denied SSH session"
                    );
                    let _ = response_tx_clone.send(Message::SshSessionOpened {
                        request_id,
                        session_id,
                        success: false,
                        error: Some("Access denied".to_string()),
                    });
                    return;
                }
                debug!(
                    session_id = %session_id, user_id = %rbac_user, asset_id = %rbac_asset,
                    "RBAC re-check granted SSH session"
                );

                // SECURITY (#4): materialise the credential from the vault
                // ciphertexts HERE, inside the proxy's own address space,
                // moments before the upstream connect. vauban-web never
                // saw the plaintext. Fail-closed: a decrypt error (no
                // vault wired, wrong key version, tampered ciphertext)
                // collapses to a session-open failure.
                let credential = match build_credential_via_vault(
                    vault_clone.as_ref(),
                    &auth_type,
                    password_ciphertext,
                    private_key_ciphertext,
                    passphrase_ciphertext,
                )
                .await
                {
                    Ok(cred) => cred,
                    Err(e) => {
                        warn!(
                            session_id = %session_id,
                            error = %e,
                            "Failed to materialise SSH credential from Vault"
                        );
                        let _ = response_tx_clone.send(Message::SshSessionOpened {
                            request_id,
                            session_id,
                            success: false,
                            error: Some("Failed to retrieve credentials".to_string()),
                        });
                        return;
                    }
                };

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

                match sessions_clone
                    .create_session(config, web_tx, audit_tx, recording_on_full)
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

        // SSH push public key (admin onboarding of a generated key pair)
        Message::SshPushPublicKey {
            request_id,
            asset_host,
            asset_port,
            username,
            public_key,
            password_ciphertext,
            expected_host_key,
        } => {
            info!(
                asset_host = %asset_host,
                asset_port = asset_port,
                "SSH push public key request"
            );

            // Same synthetic-session_id convention as fetch_host_key so
            // the supervisor-brokered FD can be matched.
            let push_session_id = format!("push-pubkey-{}", request_id);
            let preconnected_fd = if let Some(ref pending) = pending_connections {
                pending.lock().await.remove(&push_session_id)
            } else {
                None
            };

            let response_tx_clone = response_tx.clone();
            let vault_clone = vault_client.clone();

            tokio::spawn(async move {
                let result: std::result::Result<(), String> = async {
                    let vault = vault_clone
                        .as_ref()
                        .ok_or_else(|| "vault client not available".to_string())?;
                    let password = vault
                        .decrypt(DOMAIN_CREDENTIALS, &password_ciphertext)
                        .await?;
                    session::push_public_key(
                        &asset_host,
                        asset_port,
                        &username,
                        &public_key,
                        &password,
                        expected_host_key,
                        preconnected_fd,
                    )
                    .await
                    .map_err(|e| e.to_string())
                }
                .await;

                let response = match result {
                    Ok(()) => Message::SshPushPublicKeyResult {
                        request_id,
                        success: true,
                        error: None,
                    },
                    Err(e) => Message::SshPushPublicKeyResult {
                        request_id,
                        success: false,
                        error: Some(e),
                    },
                };
                let _ = response_tx_clone.send(response);
            });
        }

        // SSH test key-based authentication (admin validation of an
        // imported key pair)
        Message::SshTestKeyAuth {
            request_id,
            asset_host,
            asset_port,
            username,
            private_key_ciphertext,
            passphrase_ciphertext,
            expected_host_key,
        } => {
            info!(
                asset_host = %asset_host,
                asset_port = asset_port,
                "SSH test key auth request"
            );

            let test_session_id = format!("test-keyauth-{}", request_id);
            let preconnected_fd = if let Some(ref pending) = pending_connections {
                pending.lock().await.remove(&test_session_id)
            } else {
                None
            };

            let response_tx_clone = response_tx.clone();
            let vault_clone = vault_client.clone();

            tokio::spawn(async move {
                let result: std::result::Result<(), String> = async {
                    let vault = vault_clone
                        .as_ref()
                        .ok_or_else(|| "vault client not available".to_string())?;
                    let key_pem = vault
                        .decrypt(DOMAIN_CREDENTIALS, &private_key_ciphertext)
                        .await?;
                    let passphrase = match passphrase_ciphertext {
                        Some(ct) => Some(vault.decrypt(DOMAIN_CREDENTIALS, &ct).await?),
                        None => None,
                    };
                    session::test_key_auth(
                        &asset_host,
                        asset_port,
                        &username,
                        &key_pem,
                        passphrase.as_ref(),
                        expected_host_key,
                        preconnected_fd,
                    )
                    .await
                    .map_err(|e| e.to_string())
                }
                .await;

                let response = match result {
                    Ok(()) => Message::SshTestKeyAuthResult {
                        request_id,
                        success: true,
                        error: None,
                    },
                    Err(e) => Message::SshTestKeyAuthResult {
                        request_id,
                        success: false,
                        error: Some(e),
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
    //
    // Most of the heavy lifting now lives in shared::access_guard (so
    // vauban-proxy-rdp and future protocol proxies can share the exact
    // same fail-closed semantics). The tests below focus on the WIRING
    // inside this binary: env wiring, sandbox enrolment, dispatcher
    // spawn, and the handler call site.

    #[test]
    fn test_proxy_ssh_initialises_access_guard_from_env() {
        let source = prod_source();
        assert!(
            source.contains("AccessGuard::from_env(PROTOCOL_SSH"),
            "proxy-ssh boot must construct AccessGuard via shared::access_guard::AccessGuard::\
             from_env(PROTOCOL_SSH, ...). The shared helper enforces the fail-closed boot \
             contract (missing/invalid env -> error) and the env-removal SAFETY invariant; \
             rolling our own here would risk drift from vauban-proxy-rdp."
        );
    }

    #[test]
    fn test_proxy_ssh_access_env_fail_closed_boot() {
        let source = prod_source();
        // The shared helper attaches its own MissingEnvVar / InvalidEnvVar
        // diagnostics. We additionally surface a context() string so that
        // an SRE seeing the supervisor-side spawn failure can identify
        // *which* peer pipe is missing without having to dig into the
        // shared crate's error type.
        assert!(
            source.contains("VAUBAN_ACCESS_IPC_READ") && source.contains("VAUBAN_ACCESS_IPC_WRITE"),
            "proxy-ssh boot must mention both VAUBAN_ACCESS_IPC_READ and \
             VAUBAN_ACCESS_IPC_WRITE in its from_env context() so SREs can \
             grep the failure without reading shared crate sources"
        );
        assert!(
            source.contains("refusing to start"),
            "proxy-ssh boot must explicitly state that it refuses to start \
             without an access pipe (fail-closed boot, no degraded mode)"
        );
    }

    #[test]
    fn test_proxy_ssh_access_env_vars_consumed_by_shared_module() {
        // The shared::access_guard::from_env helper consumes (removes)
        // VAUBAN_ACCESS_IPC_READ / WRITE from env after parsing them, so
        // they cannot leak to children spawned later. We assert that
        // proxy-ssh does NOT itself remove_var these (would be a double
        // remove, harmless, but signals intent drift).
        let source = prod_source();
        assert!(
            !source.contains("remove_var(\"VAUBAN_ACCESS_IPC_READ\")"),
            "proxy-ssh must NOT remove VAUBAN_ACCESS_IPC_READ itself; the \
             shared AccessGuard::from_env helper owns that step. Duplicating \
             it here means someone is bypassing the shared contract."
        );
        assert!(
            !source.contains("remove_var(\"VAUBAN_ACCESS_IPC_WRITE\")"),
            "proxy-ssh must NOT remove VAUBAN_ACCESS_IPC_WRITE itself; the \
             shared AccessGuard::from_env helper owns that step."
        );
    }

    #[test]
    fn test_proxy_ssh_access_fds_in_sandbox() {
        let source = prod_source();
        assert!(
            source.contains("ipc_fds.extend_from_slice(&access_wiring.fds)"),
            "Access pipe FDs returned by AccessGuard::from_env (in \
             access_wiring.fds) MUST be enrolled in the Capsicum ipc_fds \
             set; otherwise the shared dispatcher will be killed on the \
             first read after sandbox entry."
        );
    }

    #[test]
    fn test_proxy_ssh_access_dispatcher_spawned() {
        let source = prod_source();
        assert!(
            source.contains("access_guard.spawn_dispatcher()"),
            "Access RBAC dispatcher MUST be spawned via \
             access_guard.spawn_dispatcher() exactly once at boot. Without \
             this call, every authorize() invocation will hit \
             RBAC_RECHECK_TIMEOUT and fail closed (the proxy stays safe but \
             becomes useless)."
        );
    }

    #[test]
    fn test_proxy_ssh_session_open_calls_authorize() {
        let source = prod_source();
        // The whole-file scope is fine here: there is only one call site
        // for `.authorize(` in production code (the SshSessionOpen
        // handler). If a future refactor ever moves it elsewhere, the
        // dispatcher-spawn check above still guarantees the wiring is
        // alive somewhere reachable from main_loop.
        assert!(
            source.contains(".authorize(&rbac_user, &rbac_asset)"),
            "SshSessionOpen handler MUST call \
             access_guard.authorize(&rbac_user, &rbac_asset).await inside \
             the spawned task (defense-in-depth RBAC re-check); see security \
             audit finding #6"
        );
        // Policy-deny, IPC-error, and timeout branches all collapse to
        // the same generic message inside `if !decision.is_granted()`.
        // We expect exactly one occurrence in the SshSessionOpen handler.
        let access_denied_count = source.matches("\"Access denied\"").count();
        assert!(
            access_denied_count >= 1,
            "Expected at least 1 occurrence of the generic \"Access denied\" \
             fail-closed reply in production code, found {}",
            access_denied_count
        );
    }

    #[test]
    fn test_proxy_ssh_authorize_runs_inside_spawn() {
        // SECURITY / LIVENESS: the authorize() call MUST live inside the
        // `tokio::spawn` block that drives create_session, NOT inline in
        // the select! arm. If it were inline, an unresponsive
        // vauban-access (dead pipe, saturated DB pool, code panic) would
        // freeze the main_loop, miss supervisor heartbeats, and trigger
        // an unresponsive-restart. That regression actually shipped
        // once; this guard prevents it from happening again. The hard
        // timeout itself is enforced inside shared::access_guard
        // (RBAC_RECHECK_TIMEOUT) and tested there; we only check the
        // call-site discipline here.
        let source = prod_source();
        let spawn_idx = source
            .find("tokio::spawn(async move {")
            .expect("SshSessionOpen handler must spawn create_session in a task");
        let check_idx = source
            .find(".authorize(&rbac_user, &rbac_asset)")
            .expect("AccessGuard.authorize call site must exist");
        assert!(
            check_idx > spawn_idx,
            "AccessGuard.authorize MUST run inside the tokio::spawn body (after the \
             `tokio::spawn(async move {{` line) so that a slow/wedged \
             vauban-access cannot block the main loop and trigger a \
             supervisor unresponsive-restart"
        );
    }

    #[test]
    fn test_proxy_ssh_metrics_wired_to_access_guard() {
        // ServiceState implements AccessGuardMetrics so that grant /
        // deny / timeout / ipc-error counters end up on the same atomics
        // that feed the Pong stats. If anyone removes the impl block,
        // operators lose visibility into vauban-access health from the
        // SSH proxy's standpoint.
        let source = prod_source();
        assert!(
            source.contains("impl AccessGuardMetrics for ServiceState"),
            "ServiceState MUST implement AccessGuardMetrics so the shared \
             AccessGuard's grant/deny/timeout/ipc-error counters feed our \
             ServiceStats. Removing this impl breaks operability."
        );
        assert!(
            source.contains("rbac_recheck_timeouts.fetch_add"),
            "ServiceState::record_timeout MUST increment rbac_recheck_timeouts \
             (the dedicated atomic) so SREs can distinguish 'access wedged' \
             from 'policy denied' from the Pong stats alone."
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

    // ==================== Cryptographic session-token gate ====================
    //
    // SECURITY: vauban-proxy-ssh MUST verify the BLAKE3-keyed session
    // token on every SshSessionOpen BEFORE the AccessGuard re-check
    // and BEFORE any upstream connection work. The token is the only
    // proof we have that vauban-access (not a compromised vauban-web)
    // authorized the EXACT (user, asset, "ssh", session_id) tuple
    // about to flow through this proxy. These tests pin the wiring so
    // the gate cannot silently regress.

    #[test]
    fn test_proxy_ssh_loads_session_token_key_at_boot() {
        let source = prod_source();
        assert!(
            source.contains("session_token_gate::init_from_env()"),
            "proxy-ssh boot MUST call session_token_gate::init_from_env() \
             so the BLAKE3 MAC key is loaded BEFORE Capsicum closes us \
             out of env mutation. Removing this call disables the \
             cryptographic gate and lets a compromised vauban-web open \
             arbitrary sessions."
        );
        let init_idx = source
            .find("session_token_gate::init_from_env()")
            .expect("init_from_env call must exist");
        let cap_enter_idx = source
            .find("capsicum::setup_service_sandbox")
            .expect("Capsicum sandbox setup must exist");
        assert!(
            init_idx < cap_enter_idx,
            "session_token_gate::init_from_env() MUST run BEFORE \
             capsicum::setup_service_sandbox. After Capsicum mode is \
             entered, env mutation is impossible and TokenKey::from_env \
             will panic on the remove_var step."
        );
    }

    #[test]
    fn test_proxy_ssh_session_open_verifies_session_token_first() {
        let source = prod_source();
        let handler_start = source
            .find("Message::SshSessionOpen {")
            .expect("SshSessionOpen handler must exist");
        let handler = &source[handler_start..];
        let verify_idx = handler.find("session_token_gate::verify_proxy(").expect(
            "SshSessionOpen handler MUST call session_token_gate::verify_proxy. \
             Without this, a compromised vauban-web could forge any \
             SshSessionOpen and bypass cryptographic authorization.",
        );
        let authorize_idx = handler
            .find(".authorize(&rbac_user, &rbac_asset)")
            .expect("AccessGuard.authorize call site must exist inside the handler");
        assert!(
            verify_idx < authorize_idx,
            "session_token_gate::verify_proxy MUST run BEFORE \
             AccessGuard.authorize. Crypto gate is the cheap, \
             local-only check; running it first means a forged token \
             never costs us an IPC round-trip to vauban-access."
        );
    }

    #[test]
    fn test_proxy_ssh_session_token_gate_uses_shared_module() {
        // Anti-regression guard: the proxy MUST consume the shared
        // `shared::session_token::proxy_gate` module instead of an
        // in-crate copy. Forking the gate into a per-proxy file is the
        // exact DRY violation we eliminated when factoring it into
        // `shared`. A reviewer who reintroduces a private module must
        // see this test fail.
        let source = prod_source();
        assert!(
            source.contains("shared::session_token::proxy_gate"),
            "proxy-ssh main.rs MUST consume \
             `shared::session_token::proxy_gate` (the single, \
             factorized cryptographic gate). Re-implementing it locally \
             defeats the whole point of the shared crate and risks \
             divergence between protocol proxies."
        );
        assert!(
            !source.contains("\nmod session_token_gate;"),
            "proxy-ssh main.rs MUST NOT declare a private \
             `session_token_gate` module — the shared module is the \
             single source of truth."
        );
    }
}
