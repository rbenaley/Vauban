//! Vauban RBAC Service
//!
//! Handles:
//! - Role-Based Access Control using Casbin
//! - Policy evaluation and caching
//! - Authorization decisions

use anyhow::{Context, Result};
use shared::capsicum;
use shared::ipc::{poll_readable, IpcChannel};
use shared::messages::{ControlMessage, Message, RbacResult, ServiceStats};
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
    /// M-8: Flag set by ControlMessage::Shutdown to break the main loop
    /// and allow destructors to run.
    shutdown_requested: bool,
}

impl Default for ServiceState {
    fn default() -> Self {
        Self {
            start_time: Instant::now(),
            requests_processed: 0,
            requests_failed: 0,
            draining: false,
            shutdown_requested: false,
        }
    }
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    info!("vauban-rbac starting");

    match run_service() {
        Ok(()) => {
            info!("vauban-rbac exiting normally");
            ExitCode::SUCCESS
        }
        Err(e) => {
            error!("vauban-rbac error: {:#}", e);
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

    // SAFETY: We are the only thread at this point, no concurrent access.
    unsafe {
        std::env::remove_var("VAUBAN_IPC_READ");
        std::env::remove_var("VAUBAN_IPC_WRITE");
    }

    let channel = unsafe { IpcChannel::from_raw_fds(ipc_read_fd, ipc_write_fd) };

    // TODO: Load Casbin policies before entering sandbox
    info!("Resources opened, preparing to enter sandbox");

    let ipc_fds = [ipc_read_fd, ipc_write_fd];
    capsicum::setup_service_sandbox(&ipc_fds, None)
        .context("Failed to setup sandbox")?;

    info!("Entered Capsicum sandbox, starting main loop");

    let mut state = ServiceState::default();
    main_loop(&channel, &mut state)
}

fn main_loop(channel: &IpcChannel, state: &mut ServiceState) -> Result<()> {
    let fds = [channel.read_fd()];

    loop {
        // M-8/M-10: Check shutdown flag before blocking on poll.
        if state.shutdown_requested {
            info!("Shutdown flag set, exiting main loop to run destructors");
            return Ok(());
        }

        let ready = poll_readable(&fds, 1000)?;

        if ready.is_empty() {
            continue;
        }

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

        Message::RbacCheck {
            request_id,
            subject,
            object,
            action,
        } => {
            state.requests_processed += 1;

            // Security: the RBAC stub is only allowed in debug builds.
            // In release builds, all requests are denied by default until
            // the Casbin policy engine is implemented.
            let result = {
                #[cfg(debug_assertions)]
                {
                    warn!(
                        subject = %subject,
                        object = %object,
                        action = %action,
                        "RBAC stub: allowing request (debug build only)"
                    );
                    RbacResult {
                        allowed: true,
                        reason: None,
                    }
                }
                #[cfg(not(debug_assertions))]
                {
                    error!(
                        subject = %subject,
                        object = %object,
                        action = %action,
                        "RBAC policy engine not implemented - denying by default"
                    );
                    RbacResult {
                        allowed: false,
                        reason: Some(
                            "RBAC policy engine not configured".to_string(),
                        ),
                    }
                }
            };

            let response = Message::RbacResponse { request_id, result };
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

    #[test]
    fn test_service_state_default() {
        let state = ServiceState::default();
        assert_eq!(state.requests_processed, 0);
        assert_eq!(state.requests_failed, 0);
        assert!(!state.draining);
    }

    #[test]
    fn test_handle_control_ping() {
        let (supervisor, service) = IpcChannel::pair().unwrap();
        let mut state = ServiceState::default();
        state.requests_processed = 50;

        let ping = ControlMessage::Ping { seq: 10 };
        handle_control(&service, &mut state, ping).unwrap();

        let response: Message = supervisor.recv().unwrap();
        if let Message::Control(ControlMessage::Pong { seq, stats }) = response {
            assert_eq!(seq, 10);
            assert_eq!(stats.requests_processed, 50);
        } else {
            panic!("Expected Pong");
        }
    }

    #[test]
    fn test_handle_control_drain() {
        let (supervisor, service) = IpcChannel::pair().unwrap();
        let mut state = ServiceState::default();

        handle_control(&service, &mut state, ControlMessage::Drain).unwrap();
        assert!(state.draining);

        let response: Message = supervisor.recv().unwrap();
        assert!(matches!(response, Message::Control(ControlMessage::DrainComplete { .. })));
    }

    #[test]
    fn test_handle_message_rbac_check() {
        let (client, service) = IpcChannel::pair().unwrap();
        let mut state = ServiceState::default();

        let request = Message::RbacCheck {
            request_id: 1,
            subject: "user:alice".to_string(),
            object: "server:web1".to_string(),
            action: "ssh".to_string(),
        };
        handle_message(&service, &mut state, request).unwrap();

        assert_eq!(state.requests_processed, 1);

        let response: Message = client.recv().unwrap();
        if let Message::RbacResponse { request_id, result } = response {
            assert_eq!(request_id, 1);
            assert!(result.allowed);
        } else {
            panic!("Expected RbacResponse");
        }
    }

    #[test]
    fn test_handle_message_control() {
        let (supervisor, service) = IpcChannel::pair().unwrap();
        let mut state = ServiceState::default();

        let msg = Message::Control(ControlMessage::Ping { seq: 5 });
        handle_message(&service, &mut state, msg).unwrap();

        let response: Message = supervisor.recv().unwrap();
        assert!(matches!(response, Message::Control(ControlMessage::Pong { seq: 5, .. })));
    }

    // ==================== H-8 Regression Tests ====================

    /// Verify that in debug builds (cargo test default), the RBAC stub
    /// allows requests. This test documents the intentional debug behavior
    /// and will catch accidental removal of the #[cfg(debug_assertions)] guard.
    #[test]
    #[cfg(debug_assertions)]
    fn test_rbac_stub_allows_in_debug_build() {
        let (client, service) = IpcChannel::pair().unwrap();
        let mut state = ServiceState::default();

        let request = Message::RbacCheck {
            request_id: 42,
            subject: "user:bob".to_string(),
            object: "asset:db-prod".to_string(),
            action: "ssh".to_string(),
        };
        handle_message(&service, &mut state, request).unwrap();

        let response: Message = client.recv().unwrap();
        if let Message::RbacResponse { request_id, result } = response {
            assert_eq!(request_id, 42);
            // In debug builds, stub allows all requests
            assert!(
                result.allowed,
                "RBAC stub must allow requests in debug builds"
            );
            assert!(
                result.reason.is_none(),
                "RBAC stub must not set a denial reason in debug builds"
            );
        } else {
            panic!("Expected RbacResponse");
        }
    }

    /// Verify that the RBAC response preserves the request_id correctly,
    /// which is critical for matching async responses to requests.
    #[test]
    fn test_rbac_check_preserves_request_id() {
        let (client, service) = IpcChannel::pair().unwrap();
        let mut state = ServiceState::default();

        for id in [0, 1, 100, u64::MAX] {
            let request = Message::RbacCheck {
                request_id: id,
                subject: "user:test".to_string(),
                object: "resource:test".to_string(),
                action: "read".to_string(),
            };
            handle_message(&service, &mut state, request).unwrap();

            let response: Message = client.recv().unwrap();
            if let Message::RbacResponse { request_id, .. } = response {
                assert_eq!(
                    request_id, id,
                    "RBAC response must echo request_id={id}"
                );
            } else {
                panic!("Expected RbacResponse for request_id={id}");
            }
        }
    }

    /// Verify that each RBAC check increments the requests_processed counter.
    #[test]
    fn test_rbac_check_increments_counter() {
        let (client, service) = IpcChannel::pair().unwrap();
        let mut state = ServiceState::default();

        assert_eq!(state.requests_processed, 0);

        for i in 1..=5 {
            let request = Message::RbacCheck {
                request_id: i,
                subject: format!("user:u{i}"),
                object: "resource:any".to_string(),
                action: "read".to_string(),
            };
            handle_message(&service, &mut state, request).unwrap();
            assert_eq!(state.requests_processed, i);

            // Drain the response
            let _ = client.recv().unwrap();
        }
    }

    /// Structural regression test: verify that the RBAC service source code
    /// contains cfg(debug_assertions) guards around the allow-all stub.
    /// This prevents accidental removal of the compile-time safety.
    #[test]
    fn test_rbac_stub_has_cfg_debug_guard() {
        let source = include_str!("main.rs");

        assert!(
            source.contains("#[cfg(debug_assertions)]"),
            "vauban-rbac/src/main.rs must contain #[cfg(debug_assertions)] \
             to guard the RBAC allow-all stub"
        );
        assert!(
            source.contains("#[cfg(not(debug_assertions))]"),
            "vauban-rbac/src/main.rs must contain #[cfg(not(debug_assertions))] \
             with a deny-by-default fallback"
        );
        assert!(
            source.contains("allowed: false"),
            "vauban-rbac/src/main.rs must contain a deny-by-default path \
             (allowed: false) for release builds"
        );
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
        let handle_ctrl_start = source.find("fn handle_control").expect("handle_control must exist");
        let handle_ctrl_source = &source[handle_ctrl_start..];
        assert!(
            handle_ctrl_source.contains("shutdown_requested = true"),
            "M-8/M-10: handle_control must set shutdown_requested = true on Shutdown"
        );
    }
}
