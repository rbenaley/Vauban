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
mod ipc;
mod session;
mod session_manager;

use anyhow::{Context, Result};
use error::SessionError;
use ipc::AsyncIpcChannel;
use session::{SessionConfig, SshCredential, fetch_host_key};
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
use tracing::{debug, error, info, warn};

/// Service runtime state (shared across async tasks).
struct ServiceState {
    start_time: Instant,
    requests_processed: AtomicU64,
    requests_failed: AtomicU64,
    draining: AtomicBool,
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
            draining: AtomicBool::new(false),
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
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    info!("vauban-proxy-ssh starting (async mode with Tokio)");

    // Build and run the Tokio runtime
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

    // SAFETY: We clear environment variables immediately after reading.
    unsafe {
        std::env::remove_var("VAUBAN_IPC_READ");
        std::env::remove_var("VAUBAN_IPC_WRITE");
        std::env::remove_var("VAUBAN_WEB_IPC_READ");
        std::env::remove_var("VAUBAN_WEB_IPC_WRITE");
        std::env::remove_var("VAUBAN_FD_PASSING_SOCKET");
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

    // TODO: Initialize RBAC, Vault, Audit clients when pipes are available
    // let rbac_client = RbacClient::new(rbac_channel)?;
    // let vault_client = VaultClient::new(vault_channel)?;
    // let audit_client = AuditClient::new(audit_channel)?;

    info!("Resources opened, preparing to enter sandbox");

    // Collect IPC file descriptors for sandboxing (read/write pipes)
    let ipc_fds = vec![supervisor_read_fd, supervisor_write_fd, web_read_fd, web_write_fd];

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

    // Create channel for sending SSH data back to web
    let (web_tx, web_rx) = mpsc::channel::<Message>(256);

    // Run the main event loop
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

    // Create a channel for spawned tasks to send IPC responses back to the main loop.
    // This allows session creation to run in the background without blocking heartbeats.
    let (response_tx, mut response_rx) = mpsc::unbounded_channel::<Message>();

    // Get pending connections reference for passing to handlers
    let pending_connections = fd_passing.as_ref().map(|fp| Arc::clone(&fp.pending));

    loop {
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
            info!("Shutdown requested");
            std::process::exit(0);
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

async fn handle_web_message(
    response_tx: &ResponseSender,
    state: Arc<ServiceState>,
    sessions: Arc<SessionManager>,
    web_tx: mpsc::Sender<Message>,
    msg: Message,
    pending_connections: Option<PendingConnections>,
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

            // TODO: Check RBAC authorization
            // let allowed = rbac_client.check(&user_id, &asset_id, "ssh").await?;
            // if !allowed { ... }

            // Build credential from received authentication data
            // TODO: In production, credentials should come from Vault
            let credential = match auth_type.as_str() {
                "private_key" => {
                    if let Some(key) = private_key {
                        SshCredential::PrivateKey {
                            key_pem: key,
                            passphrase,
                        }
                    } else {
                        let response = Message::SshSessionOpened {
                            request_id,
                            session_id,
                            success: false,
                            error: Some("Private key authentication selected but no key provided".to_string()),
                        };
                        let _ = response_tx.send(response);
                        return Ok(());
                    }
                }
                _ => {
                    // Default to password authentication
                    if let Some(pwd) = password {
                        SshCredential::Password(pwd)
                    } else {
                        let response = Message::SshSessionOpened {
                            request_id,
                            session_id,
                            success: false,
                            error: Some("Password authentication selected but no password provided".to_string()),
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
            // potentially slow SSH connections.
            let sessions_clone = Arc::clone(&sessions);
            let state_clone = Arc::clone(&state);
            let response_tx_clone = response_tx.clone();
            
            tokio::spawn(async move {
                match sessions_clone.create_session(config, web_tx).await {
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

        // Handle responses from other services (RBAC, Vault)
        Message::RbacResponse { request_id, result } => {
            debug!(
                request_id = request_id,
                allowed = result.allowed,
                "RBAC response received"
            );
            state.increment_processed();
        }

        Message::VaultCredentialResponse {
            request_id,
            credential,
        } => {
            debug!(
                request_id = request_id,
                found = credential.is_some(),
                "Vault credential response received"
            );
            state.increment_processed();
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
}
