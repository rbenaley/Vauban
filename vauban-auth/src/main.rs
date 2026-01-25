//! Vauban Authentication Service
//!
//! Handles:
//! - User authentication (password, tokens)
//! - Multi-factor authentication (TOTP/HOTP)
//! - SSO integration (OIDC/SAML)
//! - LDAP/AD synchronization

use anyhow::{Context, Result};
use shared::capsicum;
use shared::ipc::{poll_readable, IpcChannel};
use shared::messages::{AuthResult, ControlMessage, Message, ServiceStats};
use std::os::unix::io::RawFd;
use std::process::ExitCode;
use std::time::Instant;
use tracing::{error, info, warn};

/// Service runtime state.
struct ServiceState {
    start_time: Instant,
    requests_processed: u64,
    requests_failed: u64,
    draining: bool,
}

impl Default for ServiceState {
    fn default() -> Self {
        Self {
            start_time: Instant::now(),
            requests_processed: 0,
            requests_failed: 0,
            draining: false,
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

    info!("vauban-auth starting");

    match run_service() {
        Ok(()) => {
            info!("vauban-auth exiting normally");
            ExitCode::SUCCESS
        }
        Err(e) => {
            error!("vauban-auth error: {:#}", e);
            ExitCode::FAILURE
        }
    }
}

fn run_service() -> Result<()> {
    // 1. Get IPC file descriptors from environment
    let ipc_read_fd: RawFd = std::env::var("VAUBAN_IPC_READ")
        .unwrap_or_else(|_| "0".to_string())
        .parse()
        .context("Invalid VAUBAN_IPC_READ")?;
    let ipc_write_fd: RawFd = std::env::var("VAUBAN_IPC_WRITE")
        .unwrap_or_else(|_| "1".to_string())
        .parse()
        .context("Invalid VAUBAN_IPC_WRITE")?;

    // Clear environment variables immediately
    // SAFETY: We are the only thread at this point, no concurrent access.
    unsafe {
        std::env::remove_var("VAUBAN_IPC_READ");
        std::env::remove_var("VAUBAN_IPC_WRITE");
    }

    // 2. Create IPC channel from file descriptors
    // SAFETY: FDs are passed from supervisor and are valid
    let channel = unsafe { IpcChannel::from_raw_fds(ipc_read_fd, ipc_write_fd) };

    // 3. Open any required resources BEFORE entering sandbox
    // TODO: Open database connection, LDAP connection, etc.
    info!("Resources opened, preparing to enter sandbox");

    // 4. Limit FD rights and enter Capsicum capability mode
    let ipc_fds = [ipc_read_fd, ipc_write_fd];
    capsicum::setup_service_sandbox(&ipc_fds, None)
        .context("Failed to setup sandbox")?;

    info!("Entered Capsicum sandbox, starting main loop");

    // 5. Main event loop
    let mut state = ServiceState::default();
    main_loop(&channel, &mut state)
}

fn main_loop(channel: &IpcChannel, state: &mut ServiceState) -> Result<()> {
    let fds = [channel.read_fd()];

    loop {
        // Wait for incoming messages with poll()
        let ready = poll_readable(&fds, 1000)?; // 1 second timeout

        if ready.is_empty() {
            // Timeout - continue loop
            continue;
        }

        // Read and handle message
        match channel.recv() {
            Ok(msg) => {
                if let Err(e) = handle_message(channel, state, msg) {
                    warn!("Error handling message: {}", e);
                    state.requests_failed += 1;
                }
            }
            Err(shared::ipc::IpcError::ConnectionClosed) => {
                info!("IPC connection closed, exiting");
                return Ok(());
            }
            Err(e) => {
                error!("IPC receive error: {}", e);
                state.requests_failed += 1;
            }
        }
    }
}

fn handle_message(channel: &IpcChannel, state: &mut ServiceState, msg: Message) -> Result<()> {
    match msg {
        Message::Control(ctrl) => handle_control(channel, state, ctrl),

        Message::AuthRequest {
            request_id,
            username,
            credential: _,
            source_ip,
        } => {
            info!("Auth request for user {} from {}", username, source_ip);
            state.requests_processed += 1;

            // TODO: Actual authentication logic
            let result = AuthResult::Success {
                user_id: username.clone(),
                session_id: "placeholder-session".to_string(),
                roles: vec!["user".to_string()],
            };

            let response = Message::AuthResponse { request_id, result };
            channel.send(&response)?;
            Ok(())
        }

        Message::MfaVerify {
            request_id,
            challenge_id: _,
            code: _,
        } => {
            state.requests_processed += 1;

            // TODO: Actual MFA verification
            let response = Message::MfaVerifyResponse {
                request_id,
                success: true,
                session_id: Some("placeholder-session".to_string()),
            };
            channel.send(&response)?;
            Ok(())
        }

        _ => {
            warn!("Unexpected message type");
            Ok(())
        }
    }
}

fn handle_control(channel: &IpcChannel, state: &mut ServiceState, ctrl: ControlMessage) -> Result<()> {
    match ctrl {
        ControlMessage::Ping { seq } => {
            let stats = ServiceStats {
                uptime_secs: state.start_time.elapsed().as_secs(),
                requests_processed: state.requests_processed,
                requests_failed: state.requests_failed,
                active_connections: 0,
                pending_requests: 0,
            };
            let pong = Message::Control(ControlMessage::Pong { seq, stats });
            channel.send(&pong)?;
        }

        ControlMessage::Drain => {
            info!("Drain requested");
            state.draining = true;
            let response = Message::Control(ControlMessage::DrainComplete {
                pending_requests: 0,
            });
            channel.send(&response)?;
        }

        ControlMessage::Shutdown => {
            info!("Shutdown requested");
            std::process::exit(0);
        }

        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    // ==================== ServiceState Tests ====================

    #[test]
    fn test_service_state_default() {
        let state = ServiceState::default();
        assert_eq!(state.requests_processed, 0);
        assert_eq!(state.requests_failed, 0);
        assert!(!state.draining);
    }

    #[test]
    fn test_service_state_uptime() {
        let state = ServiceState::default();
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(state.start_time.elapsed().as_millis() >= 10);
    }

    // ==================== handle_control Tests ====================

    #[test]
    fn test_handle_control_ping() {
        let (supervisor, service) = IpcChannel::pair().unwrap();
        let mut state = ServiceState::default();
        state.requests_processed = 100;
        state.requests_failed = 5;

        // Handle Ping
        let ping = ControlMessage::Ping { seq: 42 };
        handle_control(&service, &mut state, ping).unwrap();

        // Read Pong response
        let response: Message = supervisor.recv().unwrap();
        if let Message::Control(ControlMessage::Pong { seq, stats }) = response {
            assert_eq!(seq, 42);
            assert_eq!(stats.requests_processed, 100);
            assert_eq!(stats.requests_failed, 5);
        } else {
            panic!("Expected Pong");
        }
    }

    #[test]
    fn test_handle_control_drain() {
        let (supervisor, service) = IpcChannel::pair().unwrap();
        let mut state = ServiceState::default();

        // Handle Drain
        let drain = ControlMessage::Drain;
        handle_control(&service, &mut state, drain).unwrap();

        // State should be draining
        assert!(state.draining);

        // Read DrainComplete response
        let response: Message = supervisor.recv().unwrap();
        if let Message::Control(ControlMessage::DrainComplete { pending_requests }) = response {
            assert_eq!(pending_requests, 0);
        } else {
            panic!("Expected DrainComplete");
        }
    }

    // ==================== handle_message Tests ====================

    #[test]
    fn test_handle_message_auth_request() {
        let (web, auth) = IpcChannel::pair().unwrap();
        let mut state = ServiceState::default();

        // Send auth request
        let request = Message::AuthRequest {
            request_id: 1,
            username: "testuser".to_string(),
            credential: b"password".to_vec(),
            source_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        };
        
        handle_message(&auth, &mut state, request).unwrap();
        
        // Verify request was processed
        assert_eq!(state.requests_processed, 1);
        
        // Read response
        let response: Message = web.recv().unwrap();
        if let Message::AuthResponse { request_id, result } = response {
            assert_eq!(request_id, 1);
            assert!(matches!(result, AuthResult::Success { .. }));
        } else {
            panic!("Expected AuthResponse");
        }
    }

    #[test]
    fn test_handle_message_mfa_verify() {
        let (web, auth) = IpcChannel::pair().unwrap();
        let mut state = ServiceState::default();

        // Send MFA verify request
        let request = Message::MfaVerify {
            request_id: 2,
            challenge_id: "chal123".to_string(),
            code: "123456".to_string(),
        };
        
        handle_message(&auth, &mut state, request).unwrap();
        
        // Verify request was processed
        assert_eq!(state.requests_processed, 1);
        
        // Read response
        let response: Message = web.recv().unwrap();
        if let Message::MfaVerifyResponse { request_id, success, session_id } = response {
            assert_eq!(request_id, 2);
            assert!(success);
            assert!(session_id.is_some());
        } else {
            panic!("Expected MfaVerifyResponse");
        }
    }

    #[test]
    fn test_handle_message_control() {
        let (supervisor, service) = IpcChannel::pair().unwrap();
        let mut state = ServiceState::default();

        // Handle Control message via handle_message
        let msg = Message::Control(ControlMessage::Ping { seq: 99 });
        handle_message(&service, &mut state, msg).unwrap();

        // Read Pong response
        let response: Message = supervisor.recv().unwrap();
        assert!(matches!(response, Message::Control(ControlMessage::Pong { seq: 99, .. })));
    }

    #[test]
    fn test_handle_message_unexpected() {
        let (_supervisor, service) = IpcChannel::pair().unwrap();
        let mut state = ServiceState::default();

        // Handle unexpected message type (should not panic)
        let msg = Message::RbacCheck {
            request_id: 1,
            subject: "user".to_string(),
            object: "resource".to_string(),
            action: "read".to_string(),
        };
        
        let result = handle_message(&service, &mut state, msg);
        assert!(result.is_ok());
    }

    // ==================== Multiple Requests Tests ====================

    #[test]
    fn test_multiple_auth_requests() {
        let (web, auth) = IpcChannel::pair().unwrap();
        let mut state = ServiceState::default();

        // Send multiple auth requests
        for i in 0..5 {
            let request = Message::AuthRequest {
                request_id: i,
                username: format!("user{}", i),
                credential: b"password".to_vec(),
                source_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            };
            handle_message(&auth, &mut state, request).unwrap();
        }

        // All requests should be processed
        assert_eq!(state.requests_processed, 5);

        // Read all responses
        for i in 0..5 {
            let response: Message = web.recv().unwrap();
            if let Message::AuthResponse { request_id, .. } = response {
                assert_eq!(request_id, i);
            } else {
                panic!("Expected AuthResponse");
            }
        }
    }

    // ==================== ServiceStats Tests ====================

    #[test]
    fn test_service_stats_in_pong() {
        let (supervisor, service) = IpcChannel::pair().unwrap();
        let mut state = ServiceState::default();
        
        // Process some requests
        state.requests_processed = 42;
        state.requests_failed = 3;

        // Wait a bit for uptime
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Send Ping
        let ping = ControlMessage::Ping { seq: 1 };
        handle_control(&service, &mut state, ping).unwrap();

        // Check stats in Pong
        let response: Message = supervisor.recv().unwrap();
        if let Message::Control(ControlMessage::Pong { stats, .. }) = response {
            assert_eq!(stats.requests_processed, 42);
            assert_eq!(stats.requests_failed, 3);
            // uptime_secs is u64, so always valid - just verify it exists
            let _ = stats.uptime_secs;
        } else {
            panic!("Expected Pong");
        }
    }
}
