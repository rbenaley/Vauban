// L-1: Relax strict clippy lints in test code where unwrap/expect/panic are idiomatic
#![cfg_attr(test, allow(
    clippy::unwrap_used, clippy::expect_used, clippy::panic,
    clippy::print_stdout, clippy::print_stderr
))]

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
use shared::capsicum;
use shared::ipc::{recv_fd, IpcChannel};
use shared::messages::{ControlMessage, Message, ServiceStats};
use std::collections::HashMap;
use std::os::unix::io::{OwnedFd, RawFd};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, trace, warn};

struct ServiceState {
    start_time: Instant,
    requests_processed: AtomicU64,
    requests_failed: AtomicU64,
    draining: AtomicBool,
    shutdown_requested: AtomicBool,
}

type PendingConnections = Arc<Mutex<HashMap<String, OwnedFd>>>;

struct FdPassingState {
    socket_fd: RawFd,
    pending: PendingConnections,
}

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

    recv_fd(socket_fd)
}

impl Default for ServiceState {
    fn default() -> Self {
        Self {
            start_time: Instant::now(),
            requests_processed: AtomicU64::new(0),
            requests_failed: AtomicU64::new(0),
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
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
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
                .add_directive("rustls=warn".parse().unwrap()),
        )
        .init();

    info!("vauban-proxy-rdp starting (async mode with Tokio + IronRDP)");

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

    // SAFETY: Single thread at this point, no concurrent env access.
    unsafe {
        std::env::remove_var("VAUBAN_IPC_READ");
        std::env::remove_var("VAUBAN_IPC_WRITE");
        std::env::remove_var("VAUBAN_WEB_IPC_READ");
        std::env::remove_var("VAUBAN_WEB_IPC_WRITE");
        std::env::remove_var("VAUBAN_FD_PASSING_SOCKET");
        std::env::remove_var("VAUBAN_RDP_VIDEO_BITRATE_BPS");
    }

    info!(video_bitrate_bps, "H.264 encoder bitrate configured");

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

    info!("Resources opened, preparing to enter sandbox");

    let ipc_fds = vec![supervisor_read_fd, supervisor_write_fd, web_read_fd, web_write_fd];
    let fd_receiver_fds: Option<Vec<RawFd>> = fd_passing_socket.map(|fd| vec![fd]);

    capsicum::setup_service_sandbox_extended(
        &ipc_fds,
        None,
        fd_receiver_fds.as_deref(),
    )
    .context("Failed to setup sandbox")?;

    info!("Entered Capsicum sandbox, starting main loop");

    let state = Arc::new(ServiceState::default());
    let sessions = Arc::new(SessionManager::with_bitrate(video_bitrate_bps));

    let (web_tx, web_rx) = mpsc::channel::<Message>(256);

    main_loop(supervisor_async, web_async, state, sessions, web_tx, web_rx, fd_passing).await
}

async fn main_loop(
    supervisor_channel: AsyncIpcChannel,
    web_channel: AsyncIpcChannel,
    state: Arc<ServiceState>,
    sessions: Arc<SessionManager>,
    web_tx: mpsc::Sender<Message>,
    mut web_rx: mpsc::Receiver<Message>,
    fd_passing: Option<Arc<FdPassingState>>,
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

async fn handle_web_message(
    response_tx: &ResponseSender,
    state: Arc<ServiceState>,
    sessions: Arc<SessionManager>,
    web_tx: mpsc::Sender<Message>,
    msg: Message,
    pending_connections: Option<PendingConnections>,
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
        } => {
            debug!(
                session_id = %session_id,
                user_id = %user_id,
                asset_host = %asset_host,
                "RDP session open request"
            );

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
                preconnected_fd,
            };

            let sessions_clone = Arc::clone(&sessions);
            let state_clone = Arc::clone(&state);
            let response_tx_clone = response_tx.clone();

            tokio::spawn(async move {
                match sessions_clone.create_session(config, web_tx).await {
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

        handle_control_message(&service_async, &state, &sessions, ControlMessage::Ping { seq: 42 })
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

    // ==================== M-8/M-10 Structural Regression Tests ====================

    fn prod_source() -> &'static str {
        let full = include_str!("main.rs");
        if let Some(idx) = full.find("#[cfg(test)]") {
            &full[..idx]
        } else {
            full
        }
    }

    #[test]
    fn test_m8_no_process_exit_in_production_code() {
        let source = prod_source();
        assert!(
            !source.contains("process::exit"),
            "M-8/M-10: service must not call process::exit() in production code"
        );
    }

    #[test]
    fn test_m8_has_shutdown_requested_flag() {
        let source = prod_source();
        assert!(
            source.contains("shutdown_requested"),
            "M-8/M-10: ServiceState must have a shutdown_requested flag"
        );
    }

    #[test]
    fn test_m8_main_loop_checks_shutdown_flag() {
        let source = prod_source();
        let loop_start = source.find("loop {").expect("main loop must exist");
        let loop_source = &source[loop_start..];
        assert!(
            loop_source.contains("shutdown_requested"),
            "M-8/M-10: main loop must check shutdown_requested flag"
        );
    }

    #[test]
    fn test_m8_handle_control_sets_shutdown_flag() {
        let source = prod_source();
        let handle_start = source.find("fn handle_control_message").expect("handle_control_message must exist");
        let handle_source = &source[handle_start..];
        assert!(
            handle_source.contains("shutdown_requested.store(true"),
            "M-8/M-10: handle_control_message must set shutdown_requested on Shutdown"
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
        let handler_start = source.find("Message::RdpSetVideoMode").expect("RdpSetVideoMode handler must exist");
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
    fn test_m8_shutdown_flag_is_atomic_bool() {
        let source = prod_source();
        assert!(
            source.contains("shutdown_requested: AtomicBool"),
            "M-8/M-10: shutdown_requested must be AtomicBool for async safety"
        );
    }

    // ==================== TCP Connection Brokering (5.6.3) Tests ====================

    #[test]
    fn test_handle_web_message_accepts_pending_connections() {
        let source = prod_source();
        let sig = source
            .find("fn handle_web_message")
            .expect("handle_web_message must exist");
        let sig_body = &source[sig..sig + 400];
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
}
