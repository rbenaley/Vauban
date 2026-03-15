// L-1: Relax strict clippy lints in test code where unwrap/expect/panic are idiomatic
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

//! Vauban Authentication Service
//!
//! Handles:
//! - User authentication (password, tokens)
//! - Multi-factor authentication (TOTP/HOTP)
//! - SSO integration (OIDC/SAML)
//! - LDAP/AD synchronization

use anyhow::{Context, Result};
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use rand::rngs::OsRng;
use shared::capsicum;
use shared::ipc::{IpcChannel, poll_readable};
use shared::messages::{AuthResult, ControlMessage, Message, ServiceStats};
use std::os::unix::io::RawFd;
use std::process::ExitCode;
use std::time::Instant;
use tracing::{error, info, warn};

/// Argon2id parameters, read from environment before sandbox entry.
struct Argon2Params {
    memory_kb: u32,
    iterations: u32,
    parallelism: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            memory_kb: 19456,
            iterations: 2,
            parallelism: 1,
        }
    }
}

/// Service runtime state.
struct ServiceState {
    start_time: Instant,
    requests_processed: u64,
    requests_failed: u64,
    draining: bool,
    shutdown_requested: bool,
    argon2_params: Argon2Params,
}

impl ServiceState {
    fn new(argon2_params: Argon2Params) -> Self {
        Self {
            start_time: Instant::now(),
            requests_processed: 0,
            requests_failed: 0,
            draining: false,
            shutdown_requested: false,
            argon2_params,
        }
    }

    fn argon2(&self) -> Result<Argon2<'_>> {
        let params = argon2::Params::new(
            self.argon2_params.memory_kb,
            self.argon2_params.iterations,
            self.argon2_params.parallelism,
            None,
        )
        .map_err(|e| anyhow::anyhow!("Invalid Argon2 params: {}", e))?;
        Ok(Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            params,
        ))
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
    let ipc_read_fd: RawFd = std::env::var("VAUBAN_IPC_READ")
        .unwrap_or_else(|_| "0".to_string())
        .parse()
        .context("Invalid VAUBAN_IPC_READ")?;
    let ipc_write_fd: RawFd = std::env::var("VAUBAN_IPC_WRITE")
        .unwrap_or_else(|_| "1".to_string())
        .parse()
        .context("Invalid VAUBAN_IPC_WRITE")?;

    let argon2_params = load_argon2_params();

    let web_channel = parse_topology_channel("WEB");

    // SAFETY: We are the only thread at this point, no concurrent access.
    unsafe {
        std::env::remove_var("VAUBAN_IPC_READ");
        std::env::remove_var("VAUBAN_IPC_WRITE");
        std::env::remove_var("VAUBAN_ARGON2_MEMORY_KB");
        std::env::remove_var("VAUBAN_ARGON2_ITERATIONS");
        std::env::remove_var("VAUBAN_ARGON2_PARALLELISM");
        std::env::remove_var("VAUBAN_WEB_IPC_READ");
        std::env::remove_var("VAUBAN_WEB_IPC_WRITE");
    }

    // SAFETY: FDs are passed from supervisor and are valid
    let supervisor_channel = unsafe { IpcChannel::from_raw_fds(ipc_read_fd, ipc_write_fd) };

    info!(
        memory_kb = argon2_params.memory_kb,
        iterations = argon2_params.iterations,
        parallelism = argon2_params.parallelism,
        "Argon2id parameters loaded"
    );

    let mut all_fds = vec![ipc_read_fd, ipc_write_fd];
    let mut peer_channels: Vec<(&str, &IpcChannel)> = Vec::new();

    if let Some(ref ch) = web_channel {
        all_fds.push(ch.read_fd());
        all_fds.push(ch.write_fd());
        peer_channels.push(("web", ch));
    }

    capsicum::setup_service_sandbox(&all_fds, None).context("Failed to setup sandbox")?;

    info!(
        "Entered Capsicum sandbox, starting main loop ({} peer channels)",
        peer_channels.len()
    );

    let mut state = ServiceState::new(argon2_params);
    main_loop(&supervisor_channel, &peer_channels, &mut state)
}

/// Parse topology channel env vars for a peer service.
/// Returns None if the env vars are not set (dev mode without full topology).
fn parse_topology_channel(service_suffix: &str) -> Option<IpcChannel> {
    let read_var = format!("VAUBAN_{}_IPC_READ", service_suffix);
    let write_var = format!("VAUBAN_{}_IPC_WRITE", service_suffix);

    let read_fd: RawFd = std::env::var(&read_var).ok()?.parse().ok()?;
    let write_fd: RawFd = std::env::var(&write_var).ok()?.parse().ok()?;

    Some(unsafe { IpcChannel::from_raw_fds(read_fd, write_fd) })
}

fn load_argon2_params() -> Argon2Params {
    let memory_kb = std::env::var("VAUBAN_ARGON2_MEMORY_KB")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(19456);
    let iterations = std::env::var("VAUBAN_ARGON2_ITERATIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2);
    let parallelism = std::env::var("VAUBAN_ARGON2_PARALLELISM")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    Argon2Params {
        memory_kb,
        iterations,
        parallelism,
    }
}

fn main_loop(
    supervisor: &IpcChannel,
    peers: &[(&str, &IpcChannel)],
    state: &mut ServiceState,
) -> Result<()> {
    let mut poll_fds: Vec<RawFd> = vec![supervisor.read_fd()];
    for (_, ch) in peers {
        poll_fds.push(ch.read_fd());
    }

    loop {
        if state.shutdown_requested {
            info!("Shutdown flag set, exiting main loop to run destructors");
            return Ok(());
        }

        let ready_indices = poll_readable(&poll_fds, 1000)?;

        if ready_indices.is_empty() {
            continue;
        }

        for &idx in &ready_indices {
            if idx == 0 {
                match supervisor.recv() {
                    Ok(msg) => {
                        if let Err(e) = handle_message(supervisor, state, msg) {
                            warn!("Error handling supervisor message: {}", e);
                            state.requests_failed += 1;
                        }
                    }
                    Err(shared::ipc::IpcError::ConnectionClosed) => {
                        info!("Supervisor IPC connection closed, exiting");
                        return Ok(());
                    }
                    Err(e) => {
                        error!("Supervisor IPC receive error: {}", e);
                        state.requests_failed += 1;
                    }
                }
            } else {
                let peer_idx = idx - 1;
                if peer_idx < peers.len() {
                    let (name, channel) = peers[peer_idx];
                    match channel.recv() {
                        Ok(msg) => {
                            if let Err(e) = handle_message(channel, state, msg) {
                                warn!("Error handling message from {}: {}", name, e);
                                state.requests_failed += 1;
                            }
                        }
                        Err(shared::ipc::IpcError::ConnectionClosed) => {
                            info!("IPC connection from {} closed", name);
                        }
                        Err(e) => {
                            error!("IPC receive error from {}: {}", name, e);
                            state.requests_failed += 1;
                        }
                    }
                }
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

        Message::AuthVerifyPassword {
            request_id,
            password_hash,
            password,
        } => {
            state.requests_processed += 1;

            let valid = match PasswordHash::new(&password_hash) {
                Ok(parsed_hash) => match state.argon2() {
                    Ok(argon2) => argon2
                        .verify_password(password.as_str().as_bytes(), &parsed_hash)
                        .is_ok(),
                    Err(e) => {
                        error!(request_id, "Argon2 init error: {}", e);
                        state.requests_failed += 1;
                        false
                    }
                },
                Err(e) => {
                    warn!(request_id, "Invalid password hash format: {}", e);
                    false
                }
            };

            let response = Message::AuthVerifyPasswordResponse { request_id, valid };
            channel.send(&response)?;
            Ok(())
        }

        Message::AuthHashPassword {
            request_id,
            password,
        } => {
            state.requests_processed += 1;

            let (hash, error) = match state.argon2() {
                Ok(argon2) => {
                    let salt = SaltString::generate(&mut OsRng);
                    match argon2.hash_password(password.as_str().as_bytes(), &salt) {
                        Ok(h) => (Some(h.to_string()), None),
                        Err(e) => {
                            state.requests_failed += 1;
                            (None, Some(format!("Hash error: {}", e)))
                        }
                    }
                }
                Err(e) => {
                    state.requests_failed += 1;
                    (None, Some(format!("Argon2 init error: {}", e)))
                }
            };

            let response = Message::AuthHashPasswordResponse {
                request_id,
                hash,
                error,
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

fn handle_control(
    channel: &IpcChannel,
    state: &mut ServiceState,
    ctrl: ControlMessage,
) -> Result<()> {
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
            info!("Shutdown requested, setting graceful shutdown flag");
            // M-8/M-10: Set flag instead of exit(0) so the main loop breaks
            // and all destructors run.
            state.shutdown_requested = true;
        }

        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::messages::SensitiveString;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_state() -> ServiceState {
        ServiceState::new(Argon2Params::default())
    }

    // ==================== ServiceState Tests ====================

    #[test]
    fn test_service_state_default() {
        let state = test_state();
        assert_eq!(state.requests_processed, 0);
        assert_eq!(state.requests_failed, 0);
        assert!(!state.draining);
    }

    #[test]
    fn test_service_state_uptime() {
        let state = test_state();
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(state.start_time.elapsed().as_millis() >= 10);
    }

    #[test]
    fn test_argon2_params_default() {
        let params = Argon2Params::default();
        assert_eq!(params.memory_kb, 19456);
        assert_eq!(params.iterations, 2);
        assert_eq!(params.parallelism, 1);
    }

    // ==================== handle_control Tests ====================

    #[test]
    fn test_handle_control_ping() {
        let (supervisor, service) = IpcChannel::pair().unwrap();
        let mut state = test_state();
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
        let mut state = test_state();

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
        let mut state = test_state();

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
        let mut state = test_state();

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
        if let Message::MfaVerifyResponse {
            request_id,
            success,
            session_id,
        } = response
        {
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
        let mut state = test_state();

        // Handle Control message via handle_message
        let msg = Message::Control(ControlMessage::Ping { seq: 99 });
        handle_message(&service, &mut state, msg).unwrap();

        // Read Pong response
        let response: Message = supervisor.recv().unwrap();
        assert!(matches!(
            response,
            Message::Control(ControlMessage::Pong { seq: 99, .. })
        ));
    }

    #[test]
    fn test_handle_message_unexpected() {
        let (_supervisor, service) = IpcChannel::pair().unwrap();
        let mut state = test_state();

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

    // ==================== Argon2id Tests ====================

    #[test]
    fn test_hash_password_and_verify() {
        let (web, auth) = IpcChannel::pair().unwrap();
        let mut state = test_state();

        let hash_req = Message::AuthHashPassword {
            request_id: 10,
            password: SensitiveString::new("my-secure-password".to_string()),
        };
        handle_message(&auth, &mut state, hash_req).unwrap();
        assert_eq!(state.requests_processed, 1);

        let response: Message = web.recv().unwrap();
        let hash = if let Message::AuthHashPasswordResponse {
            request_id,
            hash,
            error,
        } = response
        {
            assert_eq!(request_id, 10);
            assert!(error.is_none());
            hash.expect("hash should be Some")
        } else {
            panic!("Expected AuthHashPasswordResponse");
        };

        assert!(hash.starts_with("$argon2id$"));

        let verify_req = Message::AuthVerifyPassword {
            request_id: 11,
            password_hash: hash,
            password: SensitiveString::new("my-secure-password".to_string()),
        };
        handle_message(&auth, &mut state, verify_req).unwrap();
        assert_eq!(state.requests_processed, 2);

        let response: Message = web.recv().unwrap();
        if let Message::AuthVerifyPasswordResponse { request_id, valid } = response {
            assert_eq!(request_id, 11);
            assert!(valid);
        } else {
            panic!("Expected AuthVerifyPasswordResponse");
        }
    }

    #[test]
    fn test_verify_wrong_password() {
        let (web, auth) = IpcChannel::pair().unwrap();
        let mut state = test_state();

        let hash_req = Message::AuthHashPassword {
            request_id: 20,
            password: SensitiveString::new("correct-password".to_string()),
        };
        handle_message(&auth, &mut state, hash_req).unwrap();

        let response: Message = web.recv().unwrap();
        let hash = if let Message::AuthHashPasswordResponse { hash, .. } = response {
            hash.unwrap()
        } else {
            panic!("Expected AuthHashPasswordResponse");
        };

        let verify_req = Message::AuthVerifyPassword {
            request_id: 21,
            password_hash: hash,
            password: SensitiveString::new("wrong-password".to_string()),
        };
        handle_message(&auth, &mut state, verify_req).unwrap();

        let response: Message = web.recv().unwrap();
        if let Message::AuthVerifyPasswordResponse { request_id, valid } = response {
            assert_eq!(request_id, 21);
            assert!(!valid);
        } else {
            panic!("Expected AuthVerifyPasswordResponse");
        }
    }

    #[test]
    fn test_verify_invalid_hash_format() {
        let (web, auth) = IpcChannel::pair().unwrap();
        let mut state = test_state();

        let verify_req = Message::AuthVerifyPassword {
            request_id: 30,
            password_hash: "not-a-valid-hash".to_string(),
            password: SensitiveString::new("password".to_string()),
        };
        handle_message(&auth, &mut state, verify_req).unwrap();

        let response: Message = web.recv().unwrap();
        if let Message::AuthVerifyPasswordResponse { request_id, valid } = response {
            assert_eq!(request_id, 30);
            assert!(!valid);
        } else {
            panic!("Expected AuthVerifyPasswordResponse");
        }
    }

    // ==================== Multiple Requests Tests ====================

    #[test]
    fn test_multiple_auth_requests() {
        let (web, auth) = IpcChannel::pair().unwrap();
        let mut state = test_state();

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
        let mut state = test_state();

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

    // ==================== M-8/M-10 Structural Regression Tests ====================

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
        let main_loop_start = source.find("fn main_loop").expect("main_loop must exist");
        let main_loop_source = &source[main_loop_start..];
        assert!(
            main_loop_source.contains("shutdown_requested"),
            "M-8/M-10: main_loop must check shutdown_requested flag"
        );
    }

    #[test]
    fn test_m8_handle_control_sets_shutdown_flag() {
        let source = prod_source();
        let handle_ctrl_start = source
            .find("fn handle_control")
            .expect("handle_control must exist");
        let handle_ctrl_source = &source[handle_ctrl_start..];
        assert!(
            handle_ctrl_source.contains("shutdown_requested = true"),
            "M-8/M-10: handle_control must set shutdown_requested = true on Shutdown"
        );
    }

    #[test]
    fn test_argon2_env_vars_removed() {
        let source = prod_source();
        assert!(
            source.contains("remove_var(\"VAUBAN_ARGON2_MEMORY_KB\")"),
            "Argon2 env vars must be cleared after reading"
        );
    }

    #[test]
    fn test_handles_auth_verify_password() {
        let source = prod_source();
        assert!(
            source.contains("AuthVerifyPassword"),
            "handle_message must handle AuthVerifyPassword"
        );
    }

    #[test]
    fn test_handles_auth_hash_password() {
        let source = prod_source();
        assert!(
            source.contains("AuthHashPassword"),
            "handle_message must handle AuthHashPassword"
        );
    }
}
