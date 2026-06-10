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

//! Vauban RDP Proxy Service
//!
//! Handles:
//! - RDP session proxying using IronRDP (async, pure Rust)
//! - Session management for multiple concurrent connections
//! - Display update encoding (PNG regions) and streaming to vauban-web
//! - Input event forwarding from browser to RDP server
//!
//! This service uses Tokio for async I/O, matching the SSH proxy architecture.

mod error;
mod ipc;
mod session;
mod session_manager;
mod video_encoder;

use anyhow::{Context, Result};
use ipc::AsyncIpcChannel;
use session::SessionConfig;
use session_manager::SessionManager;
use shared::access_guard::{AccessGuard, AccessGuardMetrics, AccessGuardWiring, PROTOCOL_RDP};
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
use tracing::{debug, error, info, trace, warn};

struct ServiceState {
    start_time: Instant,
    requests_processed: AtomicU64,
    requests_failed: AtomicU64,
    /// Number of RBAC re-checks that hit the hard timeout against
    /// vauban-access. Mirrors vauban-proxy-ssh::ServiceState so SREs see
    /// the same dashboard shape across both proxies. Folded into
    /// `requests_failed` for the wire-level ServiceStats but kept on its
    /// own atomic so an operator can tell "policy denied" from "access
    /// tier is wedged" without re-grepping logs.
    rbac_recheck_timeouts: AtomicU64,
    draining: AtomicBool,
    shutdown_requested: AtomicBool,
}

type PendingConnections = Arc<Mutex<HashMap<String, OwnedFd>>>;

struct FdPassingState {
    socket_fd: RawFd,
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
            "rdp_proxy: receive_fd_with_retry timed out after {} attempts \
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
    /// Surfaced via Pong logs / Prometheus once we wire the exporter;
    /// kept on ServiceState (not hidden inside AccessGuard) so SREs can
    /// grab it without an extra IPC round-trip. Mirrors the SSH proxy.
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
        }
    }
}

// Wire ServiceState into the shared AccessGuard so its grant/deny/timeout/
// ipc-error counters land on the same atomics that feed the Pong stats.
//
// SECURITY/OBSERVABILITY: each variant lands on a distinct atomic so an
// operator can tell "policy denied" from "vauban-access wedged" from "RBAC
// IPC broken" by reading /metrics or the Pong log alone, without having
// to grep raw logs. Symmetric to vauban-proxy-ssh's impl.
impl AccessGuardMetrics for ServiceState {
    fn record_granted(&self) {
        // No-op on the failed counter; the success path will eventually
        // call `increment_processed` when the RDP session actually opens.
    }

    fn record_denied(&self) {
        // Policy denial: still a "request failure" from the proxy's view
        // but we do NOT inflate rbac_recheck_timeouts -- that gauge
        // means "vauban-access health", not "user lacks rights".
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
    // SAFETY: All directive strings are compile-time constants; parse() cannot fail.
    #[allow(clippy::unwrap_used)]
    let env_filter = tracing_subscriber::EnvFilter::from_default_env()
        .add_directive(tracing::Level::INFO.into())
        .add_directive("ironrdp_session=warn".parse().unwrap())
        .add_directive("ironrdp_connector=warn".parse().unwrap())
        .add_directive("ironrdp_pdu=warn".parse().unwrap())
        .add_directive("ironrdp_tls=warn".parse().unwrap())
        .add_directive("ironrdp_tokio=warn".parse().unwrap())
        .add_directive("ironrdp_graphics=warn".parse().unwrap())
        .add_directive("ironrdp_svc=warn".parse().unwrap())
        .add_directive("ironrdp_dvc=warn".parse().unwrap())
        .add_directive("ironrdp_displaycontrol=warn".parse().unwrap())
        .add_directive("ironrdp_async=warn".parse().unwrap())
        .add_directive("sspi=warn".parse().unwrap())
        .add_directive("sspi::dns=off".parse().unwrap())
        .add_directive("picky=warn".parse().unwrap())
        .add_directive("rustls=warn".parse().unwrap());

    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    info!("vauban-proxy-rdp starting (async mode with Tokio + IronRDP)");

    // VAU-001: install the aws-lc-rs CryptoProvider as the process default
    // so the TLS server-certificate pinning verifier can delegate
    // handshake-signature verification to it (proof-of-possession of the
    // pinned key). Best-effort: a non-fatal failure means another provider
    // was already installed by a dependency, which is equally acceptable.
    if tokio_rustls::rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .is_err()
    {
        debug!("Default CryptoProvider already installed");
    }

    // SAFETY: Tokio runtime creation is a startup invariant
    #[allow(clippy::expect_used)]
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to create Tokio runtime");

    match runtime.block_on(run_service()) {
        Ok(()) => {
            info!("vauban-proxy-rdp exiting normally");
            ExitCode::SUCCESS
        }
        Err(e) => {
            error!("vauban-proxy-rdp error: {:#}", e);
            ExitCode::FAILURE
        }
    }
}

async fn run_service() -> Result<()> {
    let supervisor_read_fd: RawFd = std::env::var("VAUBAN_IPC_READ")
        .unwrap_or_else(|_| "0".to_string())
        .parse()
        .context("Invalid VAUBAN_IPC_READ")?;
    let supervisor_write_fd: RawFd = std::env::var("VAUBAN_IPC_WRITE")
        .unwrap_or_else(|_| "1".to_string())
        .parse()
        .context("Invalid VAUBAN_IPC_WRITE")?;

    let web_read_fd: RawFd = std::env::var("VAUBAN_WEB_IPC_READ")
        .context("VAUBAN_WEB_IPC_READ not set")?
        .parse()
        .context("Invalid VAUBAN_WEB_IPC_READ")?;
    let web_write_fd: RawFd = std::env::var("VAUBAN_WEB_IPC_WRITE")
        .context("VAUBAN_WEB_IPC_WRITE not set")?
        .parse()
        .context("Invalid VAUBAN_WEB_IPC_WRITE")?;

    let fd_passing_socket: Option<RawFd> = std::env::var("VAUBAN_FD_PASSING_SOCKET")
        .ok()
        .and_then(|s| s.parse().ok());

    let video_bitrate_bps: u32 = std::env::var("VAUBAN_RDP_VIDEO_BITRATE_BPS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5_000_000);

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
    // mutation, and BEFORE we accept any session-open. Mirrors
    // vauban-proxy-ssh: in production, vauban-supervisor MUST set
    // VAUBAN_SESSION_TOKEN_KEY for proxy_rdp; absence is a fatal boot
    // error so that the proxy never opens an RDP session without
    // crypto-gating it.
    session_token_gate::init_from_env().context(
        "Failed to load VAUBAN_SESSION_TOKEN_KEY - vauban-proxy-rdp \
         requires the cryptographic session-token key (refusing to \
         start; sessions cannot be cryptographically gated without it)",
    )?;
    info!("session-token MAC key loaded (BLAKE3-keyed)");

    // SAFETY: Single thread at this point, no concurrent env access.
    // Note: VAUBAN_ACCESS_IPC_READ / WRITE are consumed (and removed)
    // inside AccessGuard::from_env below.
    unsafe {
        std::env::remove_var("VAUBAN_IPC_READ");
        std::env::remove_var("VAUBAN_IPC_WRITE");
        std::env::remove_var("VAUBAN_WEB_IPC_READ");
        std::env::remove_var("VAUBAN_WEB_IPC_WRITE");
        std::env::remove_var("VAUBAN_FD_PASSING_SOCKET");
        std::env::remove_var("VAUBAN_RDP_VIDEO_BITRATE_BPS");
        std::env::remove_var("VAUBAN_RECORDING_ENABLED");
        std::env::remove_var("VAUBAN_AUDIT_IPC_READ");
        std::env::remove_var("VAUBAN_AUDIT_IPC_WRITE");
    }

    info!(
        video_bitrate_bps,
        recording_enabled, "H.264 encoder bitrate configured"
    );

    let supervisor_channel =
        unsafe { IpcChannel::from_raw_fds(supervisor_read_fd, supervisor_write_fd) };
    let web_channel = unsafe { IpcChannel::from_raw_fds(web_read_fd, web_write_fd) };

    info!("IPC channels established");

    let fd_passing = fd_passing_socket.map(|fd| {
        info!("FD passing socket available (fd={})", fd);
        Arc::new(FdPassingState {
            socket_fd: fd,
            pending: Arc::new(Mutex::new(HashMap::new())),
        })
    });

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
    // terminates the service (fail-closed boot). Symmetric to
    // vauban-proxy-ssh: the supervisor wires `ProxyRdp -> Access` in its
    // TOPOLOGY and exports VAUBAN_ACCESS_IPC_READ / VAUBAN_ACCESS_IPC_WRITE.
    // Without this re-check, a compromised or buggy vauban-web could
    // single-handedly authorise outbound RDP connections (the SSH-side
    // bypass identified in the post-MFA security audit could be replayed
    // verbatim against RDP).
    let access_wiring: AccessGuardWiring =
        AccessGuard::from_env(PROTOCOL_RDP, Arc::clone(&state) as Arc<dyn AccessGuardMetrics>)
            .context(
                "Failed to wire AccessGuard from env (VAUBAN_ACCESS_IPC_READ / \
                 VAUBAN_ACCESS_IPC_WRITE) - vauban-proxy-rdp requires an access IPC pipe \
                 (refusing to start; sessions cannot be authorised without it)",
            )?;
    let access_guard = Arc::clone(&access_wiring.guard);
    info!("AccessGuard initialised (defense-in-depth RBAC re-check)");

    let audit_channel = audit_fds.map(|(r, w)| {
        let ch = unsafe { IpcChannel::from_raw_fds(r, w) };
        info!("Audit IPC channel opened for session recording");
        ch
    });

    info!("Resources opened, preparing to enter sandbox");

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
    let fd_receiver_fds: Option<Vec<RawFd>> = fd_passing_socket.map(|fd| vec![fd]);

    let sealed =
        capsicum::setup_service_sandbox_extended(&ipc_fds, None, fd_receiver_fds.as_deref())
            .context("Failed to setup sandbox")?;

    capsicum::log_main_loop_start(&sealed, "starting main loop");

    let sessions = Arc::new(SessionManager::with_bitrate(video_bitrate_bps));

    // SECURITY: Spawn the AccessGuard dispatcher. Without this task,
    // every authorize() call would hit RBAC_RECHECK_TIMEOUT (10s) and
    // fail closed -- the proxy would still be safe but useless. The
    // shared module logs at error level when the dispatcher exits, so
    // operators can detect the degraded state without re-grepping logs.
    let _dispatcher_handle = access_guard.spawn_dispatcher();

    let (web_tx, web_rx) = mpsc::channel::<Message>(256);

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

    main_loop(
        sealed,
        supervisor_async,
        web_async,
        state,
        sessions,
        web_tx,
        web_rx,
        fd_passing,
        audit_tx,
        access_guard,
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
    web_tx: mpsc::Sender<Message>,
    mut web_rx: mpsc::Receiver<Message>,
    fd_passing: Option<Arc<FdPassingState>>,
    audit_tx: Option<mpsc::Sender<Message>>,
    access_guard: Arc<AccessGuard>,
) -> Result<()> {
    info!("Main event loop started");

    let (response_tx, mut response_rx) = mpsc::unbounded_channel::<Message>();
    let pending_connections = fd_passing.as_ref().map(|fp| Arc::clone(&fp.pending));

    loop {
        if state.shutdown_requested.load(Ordering::SeqCst) {
            info!("Shutdown flag set, exiting main loop to run destructors");
            break;
        }

        tokio::select! {
            result = supervisor_channel.recv() => {
                match result {
                    Ok(Message::Control(ctrl)) => {
                        handle_control_message(&supervisor_channel, &state, &sessions, ctrl).await?;
                    }
                    Ok(Message::TcpConnectResponse { session_id, success, error, .. }) => {
                        if success {
                            if let Some(ref fp) = fd_passing {
                                let fd_result = receive_fd_with_retry(fp.socket_fd, 10, 50).await;
                                match fd_result {
                                    Ok(fd) => {
                                        debug!(session_id = %session_id, fd = ?fd, "Received TCP connection FD from supervisor");
                                        fp.pending.lock().await.insert(session_id, fd);
                                    }
                                    Err(e) if e.to_string().contains("not available") || e.to_string().contains("Unsupported") => {
                                        debug!(session_id = %session_id, "FD passing not available on this platform");
                                    }
                                    Err(e) => {
                                        error!(session_id = %session_id, error = %e, "Failed to receive FD");
                                    }
                                }
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
                        ).await {
                            warn!(error = %e, "Error handling web message");
                            state.increment_failed();
                        }
                    }
                    Err(ipc::IpcError::ConnectionClosed) => {
                        info!("Web connection closed");
                    }
                    Err(e) => {
                        error!(error = %e, "Error receiving from web");
                        state.increment_failed();
                    }
                }
            }

            Some(msg) = web_rx.recv() => {
                if let Err(e) = web_channel.send(&msg) {
                    warn!(error = %e, "Failed to send RDP data to web");
                }
            }

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
            trace!(seq = seq, "Responded to ping");
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
            state.shutdown_requested.store(true, Ordering::SeqCst);
        }
        _ => {
            debug!(?ctrl, "Ignoring control message");
        }
    }
    Ok(())
}

type ResponseSender = mpsc::UnboundedSender<Message>;

#[allow(clippy::too_many_arguments)] // dispatch handler; arguments map 1:1 onto IPC dependencies
async fn handle_web_message(
    response_tx: &ResponseSender,
    state: Arc<ServiceState>,
    sessions: Arc<SessionManager>,
    web_tx: mpsc::Sender<Message>,
    msg: Message,
    pending_connections: Option<PendingConnections>,
    audit_tx: Option<mpsc::Sender<Message>>,
    access_guard: Arc<AccessGuard>,
) -> Result<()> {
    match msg {
        Message::RdpSessionOpen {
            request_id,
            session_id,
            user_id,
            asset_id,
            asset_host,
            asset_port,
            username,
            password,
            domain,
            desktop_width,
            desktop_height,
            expected_cert_fingerprint,
            session_token,
        } => {
            debug!(
                session_id = %session_id,
                user_id = %user_id,
                asset_host = %asset_host,
                "RDP session open request"
            );

            // SECURITY: cryptographic session-token gate. See
            // vauban-proxy-ssh::handle_web_message for the full
            // rationale; same contract here.
            if !session_token_gate::verify_proxy(
                &session_token,
                &user_id,
                &asset_id,
                "rdp",
                &session_id,
            ) {
                let response = Message::RdpSessionOpened {
                    request_id,
                    session_id,
                    success: false,
                    desktop_width: 0,
                    desktop_height: 0,
                    error: Some("Access denied".to_string()),
                };
                let _ = response_tx.send(response);
                return Ok(());
            }

            if state.draining.load(Ordering::SeqCst) {
                let response = Message::RdpSessionOpened {
                    request_id,
                    session_id,
                    success: false,
                    desktop_width: 0,
                    desktop_height: 0,
                    error: Some("Service is draining, not accepting new sessions".to_string()),
                };
                let _ = response_tx.send(response);
                return Ok(());
            }

            // VAU-001: defense-in-depth fail-closed. vauban-web's connect
            // pre-flight already refuses to open a session without a pinned
            // certificate, but the proxy MUST NOT trust that alone: a
            // missing / empty pin here means "no SPKI to verify against",
            // so we refuse rather than fall back to accept-any TLS (the
            // pre-fix MITM hole). Mirrors the SSH expected_host_key contract.
            let expected_cert_fingerprint = match expected_cert_fingerprint {
                Some(fp) if !fp.trim().is_empty() => fp,
                _ => {
                    warn!(
                        session_id = %session_id,
                        "RDP session refused: no pinned server certificate (fail-closed)"
                    );
                    let response = Message::RdpSessionOpened {
                        request_id,
                        session_id,
                        success: false,
                        desktop_width: 0,
                        desktop_height: 0,
                        error: Some(
                            "No pinned RDP server certificate; refusing to connect".to_string(),
                        ),
                    };
                    let _ = response_tx.send(response);
                    return Ok(());
                }
            };

            let preconnected_fd = if let Some(ref pending) = pending_connections {
                pending.lock().await.remove(&session_id)
            } else {
                None
            };

            if preconnected_fd.is_some() {
                debug!(session_id = %session_id, "Using pre-established TCP connection from supervisor");
            }

            let config = SessionConfig {
                session_id: session_id.clone(),
                user_id,
                asset_id,
                host: asset_host,
                port: asset_port,
                username,
                password: password.map(|p| secrecy::SecretString::from(p.into_inner())),
                domain,
                desktop_width,
                desktop_height,
                expected_cert_fingerprint,
                preconnected_fd,
            };

            // Spawn session creation in a separate task to avoid blocking
            // the main loop (heartbeats, control messages). Doing the
            // RBAC re-check inline would let a wedged vauban-access
            // freeze main_loop and trigger a supervisor unresponsive-
            // restart -- the exact failure mode that shipped once on
            // proxy-ssh; see docs/runbooks/ipc_topology_debugging.md.
            let sessions_clone = Arc::clone(&sessions);
            let state_clone = Arc::clone(&state);
            let response_tx_clone = response_tx.clone();
            let access_guard_clone = Arc::clone(&access_guard);
            let rbac_user = config.user_id.clone();
            let rbac_asset = config.asset_id.clone();

            tokio::spawn(async move {
                // SECURITY: Defense-in-depth RBAC re-check via the shared
                // AccessGuard. vauban-web has already evaluated
                // authorisation before emitting RdpSessionOpen, but we
                // cannot blindly trust that gate -- a compromised or
                // buggy web tier must not be able to single-handedly
                // authorise an outbound RDP connection. AccessGuard
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
                        "RBAC re-check denied RDP session"
                    );
                    let _ = response_tx_clone.send(Message::RdpSessionOpened {
                        request_id,
                        session_id,
                        success: false,
                        desktop_width: 0,
                        desktop_height: 0,
                        error: Some("Access denied".to_string()),
                    });
                    return;
                }
                debug!(
                    session_id = %session_id, user_id = %rbac_user, asset_id = %rbac_asset,
                    "RBAC re-check granted RDP session"
                );

                match sessions_clone
                    .create_session(config, web_tx, audit_tx)
                    .await
                {
                    Ok((_sid, w, h)) => {
                        state_clone.increment_processed();
                        let response = Message::RdpSessionOpened {
                            request_id,
                            session_id,
                            success: true,
                            desktop_width: w,
                            desktop_height: h,
                            error: None,
                        };
                        let _ = response_tx_clone.send(response);
                    }
                    Err(e) => {
                        state_clone.increment_failed();
                        let response = Message::RdpSessionOpened {
                            request_id,
                            session_id,
                            success: false,
                            desktop_width: 0,
                            desktop_height: 0,
                            error: Some(e.to_string()),
                        };
                        let _ = response_tx_clone.send(response);
                    }
                }
            });
        }

        Message::RdpInput { session_id, input } => {
            if let Err(e) = sessions.send_input(&session_id, input).await {
                debug!(session_id = %session_id, error = %e, "Failed to send input to session");
            }
        }

        Message::RdpResize {
            session_id,
            width,
            height,
        } => {
            if let Err(e) = sessions.resize(&session_id, width, height).await {
                warn!(session_id = %session_id, error = %e, "Failed to resize session");
            }
        }

        Message::RdpSetVideoMode {
            session_id,
            enabled,
            ..
        } => {
            debug!(session_id = %session_id, enabled, "RDP video mode request");
            if let Err(e) = sessions.set_video_mode(&session_id, enabled).await {
                warn!(session_id = %session_id, error = %e, "Failed to set video mode");
            }
        }

        Message::RdpSessionClose { session_id } => {
            info!(session_id = %session_id, "RDP session close request");
            if let Err(e) = sessions.close_session(&session_id).await {
                warn!(session_id = %session_id, error = %e, "Failed to close session");
            }
            sessions.remove_session(&session_id).await;
        }

        Message::RdpFetchServerCert {
            request_id,
            asset_host,
            asset_port,
        } => {
            debug!(
                request_id,
                host = %asset_host,
                port = asset_port,
                "RDP server certificate fetch request (TOFU)"
            );

            // The supervisor brokered the TCP connect under this synthetic
            // session id (crypto-gated, mirrors the SSH host-key fetch).
            let fetch_key = format!("fetch-rdpcert-{request_id}");
            let preconnected_fd = if let Some(ref pending) = pending_connections {
                pending.lock().await.remove(&fetch_key)
            } else {
                None
            };

            // Spawn so a slow/hung target TLS handshake cannot freeze the
            // IPC main loop (same rationale as RdpSessionOpen).
            let response_tx_clone = response_tx.clone();
            tokio::spawn(async move {
                match session::fetch_server_cert(&asset_host, asset_port, preconnected_fd).await {
                    Ok((server_spki, cert_fingerprint)) => {
                        let _ = response_tx_clone.send(Message::RdpServerCertResult {
                            request_id,
                            success: true,
                            server_spki: Some(server_spki),
                            cert_fingerprint: Some(cert_fingerprint),
                            error: None,
                        });
                    }
                    Err(e) => {
                        warn!(request_id, error = %e, "RDP server certificate fetch failed");
                        let _ = response_tx_clone.send(Message::RdpServerCertResult {
                            request_id,
                            success: false,
                            server_spki: None,
                            cert_fingerprint: None,
                            error: Some(e.to_string()),
                        });
                    }
                }
            });
        }

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
            "service must not call process::exit() in production code"
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

    // ==================== Bitrate Security Tests ====================

    #[test]
    fn test_bitrate_env_var_read_and_destroyed() {
        let source = prod_source();
        assert!(
            source.contains("VAUBAN_RDP_VIDEO_BITRATE_BPS"),
            "Must read VAUBAN_RDP_VIDEO_BITRATE_BPS environment variable"
        );
        assert!(
            source.contains(r#"remove_var("VAUBAN_RDP_VIDEO_BITRATE_BPS")"#),
            "Must destroy VAUBAN_RDP_VIDEO_BITRATE_BPS after reading (pentest hygiene)"
        );
    }

    #[test]
    fn test_bitrate_not_received_from_ipc() {
        let source = prod_source();
        let handler_start = source
            .find("Message::RdpSetVideoMode")
            .expect("RdpSetVideoMode handler must exist");
        let handler_body = &source[handler_start..handler_start + 300];
        assert!(
            !handler_body.contains("bitrate_bps,") || handler_body.contains(".."),
            "RdpSetVideoMode handler must ignore bitrate_bps from IPC (use supervisor-injected value)"
        );
    }

    #[test]
    fn test_session_manager_created_with_bitrate() {
        let source = prod_source();
        assert!(
            source.contains("SessionManager::with_bitrate(video_bitrate_bps)"),
            "SessionManager must be created with the bitrate read from env var"
        );
    }

    #[test]
    fn test_shutdown_flag_is_atomic_bool() {
        let source = prod_source();
        assert!(
            source.contains("shutdown_requested: AtomicBool"),
            "shutdown_requested must be AtomicBool for async safety"
        );
    }

    // ==================== TCP Connection Brokering (5.6.3) Tests ====================

    #[test]
    fn test_handle_web_message_accepts_pending_connections() {
        let source = prod_source();
        let sig = source
            .find("fn handle_web_message")
            .expect("handle_web_message must exist");
        let sig_body = &source[sig..sig + 500];
        assert!(
            sig_body.contains("pending_connections: Option<PendingConnections>"),
            "handle_web_message must accept pending_connections parameter for FD brokering"
        );
    }

    #[test]
    fn test_pending_connections_passed_to_handler() {
        let source = prod_source();
        let call_site = source
            .find("handle_web_message(")
            .expect("handle_web_message call must exist");
        let call_body = &source[call_site..call_site + 400];
        assert!(
            call_body.contains("pending_connections.clone()"),
            "main_loop must pass pending_connections to handle_web_message"
        );
    }

    #[test]
    fn test_rdp_session_open_extracts_preconnected_fd() {
        let source = prod_source();
        let handler = source
            .find("Message::RdpSessionOpen")
            .expect("RdpSessionOpen handler must exist");
        let handler_body = &source[handler..];
        let handler_end = handler_body
            .find("Message::RdpInput")
            .unwrap_or(handler_body.len());
        let handler_body = &handler_body[..handler_end];

        assert!(
            handler_body.contains("pending.lock().await.remove(&session_id)"),
            "RdpSessionOpen handler must extract preconnected FD from pending_connections"
        );
        assert!(
            handler_body.contains("preconnected_fd"),
            "RdpSessionOpen handler must pass preconnected_fd to SessionConfig"
        );
    }

    #[test]
    fn test_tcp_connect_response_stores_fd() {
        let source = prod_source();
        let response_handler = source
            .find("TcpConnectResponse")
            .expect("TcpConnectResponse handler must exist");
        let handler_body = &source[response_handler..response_handler + 600];
        assert!(
            handler_body.contains("fp.pending.lock().await.insert(session_id, fd)"),
            "TcpConnectResponse handler must store received FD in pending_connections"
        );
    }

    // ==================== Defense-in-Depth RBAC Re-check Tests ====================
    //
    // These structural tests pin the invariant that vauban-proxy-rdp re-
    // verifies every RdpSessionOpen against vauban-access via the shared
    // AccessGuard module, even though vauban-web has already authorised
    // the request. Symmetric to the suite in vauban-proxy-ssh; any drift
    // between the two proxies is a security regression.

    #[test]
    fn test_proxy_rdp_imports_shared_access_guard() {
        let source = prod_source();
        assert!(
            source.contains("use shared::access_guard::"),
            "vauban-proxy-rdp must import the shared AccessGuard module \
             (defense-in-depth RBAC re-check, symmetric to proxy-ssh)"
        );
        assert!(
            source.contains("PROTOCOL_RDP"),
            "vauban-proxy-rdp must tag its AccessGuard with PROTOCOL_RDP \
             (so metrics/logs can distinguish SSH vs RDP denials)"
        );
    }

    #[test]
    fn test_proxy_rdp_initialises_access_guard_from_env() {
        let source = prod_source();
        assert!(
            source.contains("AccessGuard::from_env(PROTOCOL_RDP"),
            "vauban-proxy-rdp must call AccessGuard::from_env(PROTOCOL_RDP, ...) \
             at boot (single source of truth for VAUBAN_ACCESS_IPC_* parsing)"
        );
    }

    #[test]
    fn test_proxy_rdp_access_guard_initialised_before_sandbox() {
        let source = prod_source();
        let from_env = source
            .find("AccessGuard::from_env")
            .expect("AccessGuard::from_env call must exist");
        let sandbox = source
            .find("setup_service_sandbox_extended")
            .expect("Capsicum sandbox call must exist");
        assert!(
            from_env < sandbox,
            "AccessGuard MUST be wired BEFORE entering Capsicum sandbox \
             (fail-closed boot: missing env / invalid fd terminates the service)"
        );
    }

    #[test]
    fn test_proxy_rdp_access_fds_in_sandbox() {
        let source = prod_source();
        assert!(
            source.contains("ipc_fds.extend_from_slice(&access_wiring.fds)"),
            "vauban-proxy-rdp must add access_wiring.fds to the Capsicum \
             sandbox (otherwise authorize() would EBADF inside the sandbox)"
        );
    }

    #[test]
    fn test_proxy_rdp_access_dispatcher_spawned() {
        let source = prod_source();
        assert!(
            source.contains("access_guard.spawn_dispatcher()"),
            "vauban-proxy-rdp must spawn the AccessGuard dispatcher \
             (otherwise every authorize() hits RBAC_RECHECK_TIMEOUT and \
             the proxy becomes useless)"
        );
    }

    #[test]
    fn test_proxy_rdp_session_open_calls_authorize() {
        let source = prod_source();
        let handler = source
            .find("Message::RdpSessionOpen")
            .expect("RdpSessionOpen handler must exist");
        let handler_body = &source[handler..];
        let handler_end = handler_body
            .find("Message::RdpInput")
            .unwrap_or(handler_body.len());
        let handler_body = &handler_body[..handler_end];
        assert!(
            handler_body.contains("access_guard_clone.authorize("),
            "RdpSessionOpen handler MUST call AccessGuard::authorize \
             before opening the upstream RDP session (defense-in-depth)"
        );
        assert!(
            handler_body.contains("if !decision.is_granted()"),
            "RdpSessionOpen handler MUST fail-closed on any non-Granted \
             AccessDecision variant (Denied / Timeout / BackendError)"
        );
        assert!(
            handler_body.contains("\"Access denied\".to_string()"),
            "Denial response MUST be the generic 'Access denied' string \
             (do NOT leak Denied vs Timeout vs BackendError to the client)"
        );
    }

    #[test]
    fn test_proxy_rdp_authorize_runs_inside_spawn() {
        let source = prod_source();
        let handler = source
            .find("Message::RdpSessionOpen")
            .expect("RdpSessionOpen handler must exist");
        let handler_body = &source[handler..];
        let spawn_idx = handler_body
            .find("tokio::spawn(")
            .expect("RdpSessionOpen must spawn its work in a task");
        let auth_idx = handler_body
            .find("access_guard_clone.authorize(")
            .expect("authorize() call must exist");
        assert!(
            spawn_idx < auth_idx,
            "authorize() MUST run inside tokio::spawn so a wedged \
             vauban-access cannot block main_loop and trigger an \
             unresponsive-restart from the supervisor"
        );
    }

    #[test]
    fn test_proxy_rdp_metrics_wired_to_access_guard() {
        let source = prod_source();
        assert!(
            source.contains("impl AccessGuardMetrics for ServiceState"),
            "ServiceState must implement AccessGuardMetrics so AccessGuard \
             grants/denies/timeouts/ipc-errors land on the same atomics \
             that feed Pong stats"
        );
        assert!(
            source.contains("rbac_recheck_timeouts: AtomicU64"),
            "ServiceState must own a dedicated rbac_recheck_timeouts \
             atomic (distinguishes 'access tier wedged' from 'policy \
             denied' for SREs)"
        );
    }

    #[test]
    fn test_proxy_rdp_no_legacy_inline_rbac_client() {
        // Anti-regression: any reintroduction of an in-crate
        // AccessRbacClient (the pattern we just factored out of
        // proxy-ssh) is a code-duplication regression and would also
        // skip the AccessGuardMetrics wiring.
        let source = prod_source();
        assert!(
            !source.contains("struct AccessRbacClient"),
            "vauban-proxy-rdp MUST NOT redeclare AccessRbacClient \
             locally; use shared::access_guard instead"
        );
    }

    #[test]
    fn test_pending_connections_is_active() {
        let source = prod_source();
        assert!(
            !source.contains("let _pending_connections"),
            "pending_connections must not be prefixed with underscore (must be actively used)"
        );
        assert!(
            source.contains("let pending_connections = fd_passing"),
            "pending_connections must be actively used in main_loop"
        );
    }

    // ==================== Cryptographic session-token gate ====================
    //
    // SECURITY: vauban-proxy-rdp MUST verify the BLAKE3-keyed session
    // token on every RdpSessionOpen BEFORE the AccessGuard re-check.
    // Mirrors vauban-proxy-ssh: the token is the only proof that
    // vauban-access (not a compromised vauban-web) authorized the
    // EXACT (user, asset, "rdp", session_id) tuple. These tests pin
    // the wiring so the gate cannot silently regress.

    #[test]
    fn test_proxy_rdp_loads_session_token_key_at_boot() {
        let source = prod_source();
        assert!(
            source.contains("session_token_gate::init_from_env()"),
            "proxy-rdp boot MUST call session_token_gate::init_from_env() \
             so the BLAKE3 MAC key is loaded BEFORE Capsicum closes us \
             out of env mutation."
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
             capsicum::setup_service_sandbox."
        );
    }

    #[test]
    fn test_proxy_rdp_session_open_verifies_session_token_first() {
        let source = prod_source();
        let handler_start = source
            .find("Message::RdpSessionOpen {")
            .expect("RdpSessionOpen handler must exist");
        let handler = &source[handler_start..];
        let verify_idx = handler
            .find("session_token_gate::verify_proxy(")
            .expect("RdpSessionOpen handler MUST call session_token_gate::verify_proxy.");
        let authorize_idx = handler
            .find("access_guard_clone.authorize(")
            .expect("AccessGuard.authorize call site must exist inside the handler");
        assert!(
            verify_idx < authorize_idx,
            "session_token_gate::verify_proxy MUST run BEFORE \
             AccessGuard.authorize."
        );
    }

    #[test]
    fn test_proxy_rdp_session_token_gate_uses_shared_module() {
        // Anti-regression guard: the proxy MUST consume the shared
        // `shared::session_token::proxy_gate` module instead of an
        // in-crate copy. Forking the gate into a per-proxy file is the
        // exact DRY violation we eliminated when factoring it into
        // `shared`. A reviewer who reintroduces a private module must
        // see this test fail.
        let source = prod_source();
        assert!(
            source.contains("shared::session_token::proxy_gate"),
            "proxy-rdp main.rs MUST consume \
             `shared::session_token::proxy_gate` (the single, \
             factorized cryptographic gate). Re-implementing it \
             locally defeats the whole point of the shared crate and \
             risks divergence between protocol proxies."
        );
        assert!(
            !source.contains("\nmod session_token_gate;"),
            "proxy-rdp main.rs MUST NOT declare a private \
             `session_token_gate` module — the shared module is the \
             single source of truth."
        );
    }
}
