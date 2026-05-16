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

//! Vauban IACS Tunnel Proxy
//!
//! `vauban-proxy-iacs` hosts the russh sshd that EWS hosts connect to
//! with `ssh -L`, and brokers the upstream TCP connection to the
//! industrial asset (`asset.hostname:asset.port`) via the supervisor's
//! SCM_RIGHTS broker. See
//! [`docs/technical/Vauban_IACS_Proxy_Architecture_EN(1.0).md`] for
//! the full architecture.
//!
//! Bootstrap order (mirrors `vauban-proxy-ssh`):
//!
//! 1. Read IPC FDs (supervisor, web, access, audit) from env.
//! 2. Read the pre-bound IACS listener FD from
//!    `VAUBAN_IACS_LISTENER_FD` (the supervisor `bind()`s in
//!    privileged mode and inherits the FD across fork+exec).
//! 3. Load the BLAKE3 session-token MAC key.
//! 4. Wire `AccessGuard` (defense-in-depth re-check on every
//!    `direct-tcpip`).
//! 5. Enter Capsicum capability mode -- after this point, no new
//!    `socket()`, no new `bind()`, no new `connect()`. All upstream
//!    TCP goes through the supervisor's SCM_RIGHTS broker.
//! 6. Run the russh server on the inherited listener FD.

mod auth;
mod ipc;
mod registry;
mod relay;
mod server;
mod upstream;

use anyhow::{Context, Result};
use shared::access_guard::{
    AccessGuard, AccessGuardMetrics, AccessGuardWiring, PROTOCOL_IACS_TUNNEL,
};
use shared::capsicum;
use shared::ipc::{IpcChannel, recv_fd};
use shared::messages::{ControlMessage, Message, ServiceStats};
use shared::session_token::proxy_gate as session_token_gate;
use std::collections::HashMap;
use std::os::fd::FromRawFd;
use std::os::unix::io::{OwnedFd, RawFd};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::auth::{PendingSessions, PendingTunnel};
use crate::ipc::AsyncIpcChannel;
use crate::registry::TunnelRegistry;
use crate::server::{IacsTunnelServer, build_server_config, load_or_generate_host_key};
use crate::upstream::{PendingConnections, SupervisorBrokerOpener};

/// Service runtime state (shared across async tasks).
struct ServiceState {
    start_time: Instant,
    requests_processed: AtomicU64,
    requests_failed: AtomicU64,
    rbac_recheck_timeouts: AtomicU64,
    draining: AtomicBool,
    shutdown_requested: AtomicBool,
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
    fn stats(&self, active: u32) -> ServiceStats {
        ServiceStats {
            uptime_secs: self.start_time.elapsed().as_secs(),
            requests_processed: self.requests_processed.load(Ordering::SeqCst),
            requests_failed: self.requests_failed.load(Ordering::SeqCst),
            active_connections: active,
            pending_requests: 0,
        }
    }
}

impl AccessGuardMetrics for ServiceState {
    fn record_granted(&self) {}
    fn record_denied(&self) {
        self.requests_failed.fetch_add(1, Ordering::SeqCst);
    }
    fn record_timeout(&self) {
        self.rbac_recheck_timeouts.fetch_add(1, Ordering::SeqCst);
        self.requests_failed.fetch_add(1, Ordering::SeqCst);
    }
    fn record_ipc_error(&self) {
        self.requests_failed.fetch_add(1, Ordering::SeqCst);
    }
}

/// Receive a file descriptor with retry and async polling.
///
/// The FD and IPC notification travel on separate channels, so there
/// is a race condition: the `TcpConnectResponse` message can land on
/// the IPC pipe before the SCM_RIGHTS FD lands on the FD-passing
/// socket. Poll the socket and retry until the FD arrives or the
/// max-retries is exhausted (mirrors the SSH proxy implementation).
async fn receive_fd_with_retry(
    socket_fd: RawFd,
    max_retries: u32,
    delay_ms: u64,
) -> std::result::Result<OwnedFd, shared::ipc::IpcError> {
    use shared::ipc::poll_readable;

    for attempt in 0..max_retries {
        match poll_readable(&[socket_fd], 0) {
            Ok(ready) if !ready.is_empty() => {
                return recv_fd(socket_fd);
            }
            Ok(_) => {
                if attempt < max_retries - 1 {
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                }
            }
            Err(e) => {
                warn!(attempt, error = %e, "iacs_tunnel: poll_readable failed");
                if attempt < max_retries - 1 {
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                }
            }
        }
    }
    recv_fd(socket_fd)
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    info!("vauban-proxy-iacs starting (async mode with Tokio)");

    #[allow(clippy::expect_used)]
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to create Tokio runtime");

    match runtime.block_on(run_service()) {
        Ok(()) => {
            info!("vauban-proxy-iacs exiting normally");
            ExitCode::SUCCESS
        }
        Err(e) => {
            error!("vauban-proxy-iacs error: {:#}", e);
            ExitCode::FAILURE
        }
    }
}

async fn run_service() -> Result<()> {
    // === 1. Read IPC file descriptors from env.
    let supervisor_read_fd: RawFd = std::env::var("VAUBAN_IPC_READ")
        .unwrap_or_else(|_| "0".to_string())
        .parse()
        .context("Invalid VAUBAN_IPC_READ")?;
    let supervisor_write_fd: RawFd = std::env::var("VAUBAN_IPC_WRITE")
        .unwrap_or_else(|_| "1".to_string())
        .parse()
        .context("Invalid VAUBAN_IPC_WRITE")?;

    let web_read_fd: RawFd = std::env::var("VAUBAN_WEB_IPC_READ")
        .context("VAUBAN_WEB_IPC_READ not set - supervisor must provide web IPC channel")?
        .parse()
        .context("Invalid VAUBAN_WEB_IPC_READ")?;
    let web_write_fd: RawFd = std::env::var("VAUBAN_WEB_IPC_WRITE")
        .context("VAUBAN_WEB_IPC_WRITE not set - supervisor must provide web IPC channel")?
        .parse()
        .context("Invalid VAUBAN_WEB_IPC_WRITE")?;

    let audit_fds: Option<(RawFd, RawFd)> = match (
        std::env::var("VAUBAN_AUDIT_IPC_READ").ok(),
        std::env::var("VAUBAN_AUDIT_IPC_WRITE").ok(),
    ) {
        (Some(r), Some(w)) => match (r.parse::<RawFd>(), w.parse::<RawFd>()) {
            (Ok(r), Ok(w)) => Some((r, w)),
            _ => None,
        },
        _ => None,
    };

    // === 2. The supervisor pre-binds the IACS sshd listener and
    // hands the FD via env. Without it the proxy stays idle but
    // alive (heartbeats keep flowing so the supervisor does not
    // restart us in a hot loop).
    let listener_fd: Option<RawFd> = std::env::var("VAUBAN_IACS_LISTENER_FD")
        .ok()
        .and_then(|s| s.parse().ok());

    let fd_passing_socket: Option<RawFd> = std::env::var("VAUBAN_FD_PASSING_SOCKET")
        .ok()
        .and_then(|s| s.parse().ok());

    let host_key_path = std::env::var("VAUBAN_IACS_HOST_KEY_PATH")
        .unwrap_or_else(|_| "/var/lib/vauban/iacs_tunnel_host_ed25519".to_string());

    // === 3. Load and clear the BLAKE3 session-token MAC key.
    session_token_gate::init_from_env().context(
        "Failed to load VAUBAN_SESSION_TOKEN_KEY - vauban-proxy-iacs \
         requires the cryptographic session-token key (refusing to \
         start; tunnels cannot be cryptographically gated without it)",
    )?;
    info!("session-token MAC key loaded (BLAKE3-keyed)");

    // SAFETY: We are single-threaded at this point; clear env vars
    // so they do not leak into descendants (defence-in-depth).
    unsafe {
        std::env::remove_var("VAUBAN_IPC_READ");
        std::env::remove_var("VAUBAN_IPC_WRITE");
        std::env::remove_var("VAUBAN_WEB_IPC_READ");
        std::env::remove_var("VAUBAN_WEB_IPC_WRITE");
        std::env::remove_var("VAUBAN_AUDIT_IPC_READ");
        std::env::remove_var("VAUBAN_AUDIT_IPC_WRITE");
        std::env::remove_var("VAUBAN_FD_PASSING_SOCKET");
        std::env::remove_var("VAUBAN_IACS_LISTENER_FD");
        std::env::remove_var("VAUBAN_IACS_HOST_KEY_PATH");
    }

    let supervisor_channel =
        unsafe { IpcChannel::from_raw_fds(supervisor_read_fd, supervisor_write_fd) };
    let web_channel = unsafe { IpcChannel::from_raw_fds(web_read_fd, web_write_fd) };
    info!("IPC channels established");

    let state = Arc::new(ServiceState::default());

    // === 4. AccessGuard wiring (defense-in-depth RBAC re-check).
    #[rustfmt::skip]
    let access_wiring: AccessGuardWiring =
        AccessGuard::from_env(
            PROTOCOL_IACS_TUNNEL,
            Arc::clone(&state) as Arc<dyn AccessGuardMetrics>,
        )
        .context(
            "Failed to wire AccessGuard from env (VAUBAN_ACCESS_IPC_READ \
             / VAUBAN_ACCESS_IPC_WRITE) - vauban-proxy-iacs requires an \
             access IPC pipe (refusing to start; tunnels cannot be \
             authorised without it)",
        )?;
    let access_guard = Arc::clone(&access_wiring.guard);
    info!("AccessGuard initialised (defense-in-depth RBAC re-check for iacs_tunnel)");

    let audit_channel = audit_fds.map(|(r, w)| {
        let ch = unsafe { IpcChannel::from_raw_fds(r, w) };
        info!("Audit IPC channel opened for tunnel events");
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
    let listener_fds: Option<Vec<RawFd>> = listener_fd.map(|fd| vec![fd]);

    // === 5. Capsicum sandbox. After this point, the proxy can
    // ONLY read/write its IPC pipes, accept() on the inherited
    // listener FD, and recvmsg() on the FD-passing socket. No
    // new socket(), no new bind(), no new connect().
    capsicum::setup_service_sandbox_with_listeners(
        &ipc_fds,
        None, // No DB connection.
        fd_receiver_fds.as_deref(),
        listener_fds.as_deref(),
    )
    .context("Failed to setup sandbox")?;
    info!("Entered Capsicum sandbox");

    // === 6. Build the russh server.
    let registry = TunnelRegistry::new();
    let pending = PendingSessions::new();
    let pending_connections: PendingConnections = Arc::new(Mutex::new(HashMap::new()));

    // Outbound supervisor pipe writer: the SupervisorBrokerOpener
    // pushes `TcpConnectRequest` messages on this channel; a
    // dedicated writer task consumes them so we never have two
    // tasks racing on the same `IpcChannel::send`.
    let (sup_tx, mut sup_rx) = mpsc::unbounded_channel::<Message>();

    let upstream: Arc<dyn server::UpstreamOpener> = Arc::new(SupervisorBrokerOpener {
        supervisor_tx: sup_tx.clone(),
        pending_connections: Arc::clone(&pending_connections),
        fd_wait: Duration::from_secs(15),
        next_request_id: AtomicU64::new(1),
    });

    let host_key = load_or_generate_host_key(&host_key_path.into())
        .context("Failed to load/generate IACS sshd host key")?;
    let server_config = build_server_config(host_key);

    // Spawn the russh accept loop on the inherited listener FD.
    if let Some(fd) = listener_fd {
        // SAFETY: the FD was inherited from the supervisor across
        // fork+exec. We wrap it in a std listener and hand it to
        // tokio.
        let std_listener = unsafe { std::net::TcpListener::from_raw_fd(fd) };
        std_listener
            .set_nonblocking(true)
            .context("set_nonblocking on inherited IACS listener")?;
        // Extract the actual bind address from the inherited FD so
        // the operator sees the bound `host:port` in the proxy log
        // (the supervisor's `Pre-bound IACS sshd listening socket`
        // line is emitted before the children's stdout is wired up
        // to the same console buffer and may not surface in dev).
        let iacs_bind_addr = std_listener
            .local_addr()
            .map(|sa| sa.to_string())
            .unwrap_or_else(|_| "<unknown>".to_string());
        info!(
            iacs_listener_fd = fd,
            iacs_bind_addr = %iacs_bind_addr,
            "IACS listener FD inherited from supervisor"
        );
        let tokio_listener = tokio::net::TcpListener::from_std(std_listener)
            .context("tokio::net::TcpListener::from_std on inherited IACS listener")?;

        let accept_registry = registry.clone();
        let accept_pending = pending.clone();
        let accept_upstream = Arc::clone(&upstream);
        let accept_config = Arc::clone(&server_config);
        let accept_bind_addr = iacs_bind_addr.clone();
        tokio::spawn(async move {
            info!(iacs_bind_addr = %accept_bind_addr, "iacs_tunnel: accept loop started");
            loop {
                match tokio_listener.accept().await {
                    Ok((stream, peer)) => {
                        debug!(?peer, "iacs_tunnel: accepted EWS connection");
                        let mut server = IacsTunnelServer::new(
                            accept_registry.clone(),
                            accept_pending.clone(),
                            Arc::clone(&accept_upstream),
                        );
                        let cfg = Arc::clone(&accept_config);
                        let handler = russh::server::Server::new_client(&mut server, Some(peer));
                        tokio::spawn(async move {
                            if let Err(e) =
                                russh::server::run_stream(cfg, stream, handler).await
                            {
                                debug!(?peer, error = ?e, "iacs_tunnel: russh stream ended");
                            }
                        });
                    }
                    Err(e) => {
                        warn!(error = %e, "iacs_tunnel: accept failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        });
    } else {
        info!(
            "VAUBAN_IACS_LISTENER_FD not set; vauban-proxy-iacs idle \
             (industrial.iacs_tunnel.enabled = false)"
        );
    }

    // Spawn the AccessGuard dispatcher.
    let _dispatcher_handle = access_guard.spawn_dispatcher();

    // === Async wrappers + writer task for the supervisor pipe.
    let supervisor_async = Arc::new(
        AsyncIpcChannel::new(supervisor_channel)
            .context("Failed to create async supervisor channel")?,
    );
    let web_async = Arc::new(
        AsyncIpcChannel::new(web_channel).context("Failed to create async web channel")?,
    );

    {
        let sup_writer = Arc::clone(&supervisor_async);
        tokio::spawn(async move {
            while let Some(msg) = sup_rx.recv().await {
                if let Err(e) = sup_writer.send(&msg) {
                    error!(error = %e, "iacs_tunnel: supervisor send failed");
                }
            }
        });
    }

    drop(audit_channel);

    main_loop(
        supervisor_async,
        web_async,
        state,
        registry,
        pending,
        pending_connections,
        fd_passing_socket,
        access_guard,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn main_loop(
    supervisor: Arc<AsyncIpcChannel>,
    web: Arc<AsyncIpcChannel>,
    state: Arc<ServiceState>,
    registry: TunnelRegistry,
    pending: PendingSessions,
    pending_connections: PendingConnections,
    fd_passing_socket: Option<RawFd>,
    access_guard: Arc<AccessGuard>,
) -> Result<()> {
    info!("Main event loop started");
    loop {
        if state.shutdown_requested.load(Ordering::SeqCst) {
            info!("Shutdown flag set, exiting main loop");
            break;
        }

        tokio::select! {
            // Supervisor: control + TcpConnectResponse.
            result = supervisor.recv() => {
                match result {
                    Ok(Message::Control(ctrl)) => match ctrl {
                        ControlMessage::Ping { seq } => {
                            let stats = state.stats(registry.len() as u32);
                            let _ = supervisor.send(
                                &Message::Control(ControlMessage::Pong { seq, stats }),
                            );
                        }
                        ControlMessage::Drain => {
                            info!("Drain requested");
                            state.draining.store(true, Ordering::SeqCst);
                            let _ = supervisor.send(&Message::Control(
                                ControlMessage::DrainComplete {
                                    pending_requests: registry.len() as u32,
                                },
                            ));
                        }
                        ControlMessage::Shutdown => {
                            info!("Shutdown requested");
                            state.shutdown_requested.store(true, Ordering::SeqCst);
                        }
                        _ => {
                            debug!("Unhandled supervisor control message");
                        }
                    },
                    Ok(Message::TcpConnectResponse {
                        session_id,
                        success,
                        error,
                        ..
                    }) => {
                        if success {
                            if let Some(fd_socket) = fd_passing_socket {
                                match receive_fd_with_retry(fd_socket, 10, 50).await {
                                    Ok(fd) => {
                                        debug!(
                                            session_id = %session_id,
                                            "iacs_tunnel: brokered FD received from supervisor"
                                        );
                                        pending_connections
                                            .lock()
                                            .await
                                            .insert(session_id, fd);
                                    }
                                    Err(e) => {
                                        error!(
                                            session_id = %session_id, error = %e,
                                            "iacs_tunnel: failed to recv brokered FD"
                                        );
                                    }
                                }
                            } else {
                                warn!(
                                    session_id = %session_id,
                                    "iacs_tunnel: TcpConnectResponse but no FD-passing socket"
                                );
                            }
                        } else {
                            warn!(
                                session_id = %session_id, error = ?error,
                                "iacs_tunnel: supervisor TCP connect failed"
                            );
                        }
                    }
                    Ok(other) => {
                        debug!(?other, "Unhandled supervisor message");
                    }
                    Err(e) => {
                        warn!(error = %e, "Supervisor channel error");
                        break;
                    }
                }
            }

            // vauban-web: IacsTunnelOpen + IacsTunnelTerminate.
            result = web.recv() => {
                match result {
                    Ok(msg) => {
                        handle_web_message(
                            Arc::clone(&web),
                            Arc::clone(&state),
                            pending.clone(),
                            registry.clone(),
                            Arc::clone(&access_guard),
                            msg,
                        )
                        .await;
                    }
                    Err(e) => {
                        warn!(error = %e, "Web channel error");
                        break;
                    }
                }
            }
        }
    }
    Ok(())
}

async fn handle_web_message(
    web: Arc<AsyncIpcChannel>,
    state: Arc<ServiceState>,
    pending: PendingSessions,
    registry: TunnelRegistry,
    access_guard: Arc<AccessGuard>,
    msg: Message,
) {
    match msg {
        Message::IacsTunnelOpen {
            request_id,
            session_id,
            user_uuid,
            asset_uuid,
            ews_uuid,
            ews_pubkey_fp,
            asset_host,
            asset_port,
            industrial_protocol,
            ttl_seconds,
            session_token,
        } => {
            // SECURITY: cryptographic session-token gate. Verify the
            // BLAKE3-keyed MAC bound to (user_uuid, asset_uuid,
            // "iacs_tunnel", session_id) against the local
            // proxy MAC key. A compromised vauban-web cannot synth
            // a token for another user / asset / protocol because
            // it has no access to the MAC key. Fail-closed deny.
            if !session_token_gate::verify_proxy(
                &session_token,
                &user_uuid,
                &asset_uuid,
                shared::access_guard::PROTOCOL_IACS_TUNNEL,
                &session_id,
            ) {
                warn!(
                    session_id = %session_id,
                    "iacs_tunnel: session-token verify_proxy failed"
                );
                let _ = web.send(&Message::IacsTunnelOpened {
                    request_id,
                    session_id,
                    success: false,
                    error: Some("Access denied".to_string()),
                });
                state.requests_failed.fetch_add(1, Ordering::SeqCst);
                return;
            }

            if state.draining.load(Ordering::SeqCst) {
                let _ = web.send(&Message::IacsTunnelOpened {
                    request_id,
                    session_id,
                    success: false,
                    error: Some("Service draining".to_string()),
                });
                return;
            }

            // SECURITY: defense-in-depth RBAC re-check. vauban-web
            // already gated on Casbin + access-rule before minting,
            // and access minted the token only after a rule re-check.
            // This third layer catches a stale Casbin cache or a
            // mid-flight rule revoke (between mint and IacsTunnelOpen).
            // Fail-closed on Denied / Timeout / BackendError.
            let decision = access_guard.authorize(&user_uuid, &asset_uuid).await;
            if !decision.is_granted() {
                warn!(
                    session_id = %session_id,
                    user_uuid = %user_uuid,
                    asset_uuid = %asset_uuid,
                    ?decision,
                    "iacs_tunnel: AccessGuard re-check denied tunnel open"
                );
                let _ = web.send(&Message::IacsTunnelOpened {
                    request_id,
                    session_id,
                    success: false,
                    error: Some("Access denied".to_string()),
                });
                return;
            }

            // Materialise the pending entry. UUID parsing failure
            // collapses to an Access denied response so we never
            // leak which leg of the validation failed.
            let parse = || {
                Some((
                    Uuid::parse_str(&session_id).ok()?,
                    Uuid::parse_str(&user_uuid).ok()?,
                    Uuid::parse_str(&asset_uuid).ok()?,
                    Uuid::parse_str(&ews_uuid).ok()?,
                ))
            };
            let (sess, user, asset, ews) = match parse() {
                Some(t) => t,
                None => {
                    let _ = web.send(&Message::IacsTunnelOpened {
                        request_id,
                        session_id,
                        success: false,
                        error: Some("Invalid identifiers".to_string()),
                    });
                    state.requests_failed.fetch_add(1, Ordering::SeqCst);
                    return;
                }
            };

            let entry = PendingTunnel {
                session_uuid: sess,
                user_uuid: user,
                asset_uuid: asset,
                ews_uuid: ews,
                ews_pubkey_fp,
                asset_host,
                asset_port,
                industrial_protocol,
                session_token,
                deadline: Instant::now() + Duration::from_secs(ttl_seconds as u64),
            };
            let _previous = pending.insert(entry).await;

            info!(
                session_id = %session_id,
                user_uuid = %user_uuid,
                asset_uuid = %asset_uuid,
                "iacs_tunnel: pending tunnel materialised"
            );
            state.requests_processed.fetch_add(1, Ordering::SeqCst);
            let _ = web.send(&Message::IacsTunnelOpened {
                request_id,
                session_id,
                success: true,
                error: None,
            });
        }

        Message::IacsTunnelTerminate {
            session_id, reason, ..
        } => {
            let parsed = match Uuid::parse_str(&session_id) {
                Ok(u) => u,
                Err(_) => {
                    debug!(
                        session_id = %session_id,
                        "iacs_tunnel: terminate ignored (invalid uuid)"
                    );
                    return;
                }
            };
            let _expired_pending = pending.take(&parsed).await;
            registry.close_and_remove(&parsed);
            info!(
                session_id = %session_id,
                reason = %reason,
                "iacs_tunnel: terminate processed"
            );
        }

        other => {
            debug!(?other, "iacs_tunnel: unhandled web message");
        }
    }
}
