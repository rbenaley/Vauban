//! Vauban Audit Service
//!
//! Handles:
//! - WORM (Write Once Read Many) audit storage
//! - Session recording storage
//! - Real-time alerts
//! - Audit log queries

use anyhow::{Context, Result};
use shared::capsicum;
use shared::ipc::{poll_readable, IpcChannel};
use shared::messages::{ControlMessage, Message, ServiceStats};
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

    info!("vauban-audit starting");

    match run_service() {
        Ok(()) => {
            info!("vauban-audit exiting normally");
            ExitCode::SUCCESS
        }
        Err(e) => {
            error!("vauban-audit error: {:#}", e);
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

    // TODO: Open audit log files, S3 connection before entering sandbox
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

        Message::AuditEvent {
            timestamp,
            event_type,
            user_id,
            session_id,
            source_ip,
            details,
        } => {
            info!(
                "Audit event: {:?} user={:?} session={:?} ip={:?} - {}",
                event_type, user_id, session_id, source_ip, details
            );
            state.requests_processed += 1;

            // TODO: Write to WORM storage
            let response = Message::AuditAck { timestamp };
            channel.send(&response)?;
            Ok(())
        }

        Message::SessionRecordingChunk {
            session_id,
            sequence,
            data,
        } => {
            info!(
                "Session recording chunk: session={} seq={} size={}",
                session_id,
                sequence,
                data.len()
            );
            state.requests_processed += 1;

            // TODO: Write to S3/MinIO storage
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
    use shared::messages::AuditEventType;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_service_state_default() {
        let state = ServiceState::default();
        assert_eq!(state.requests_processed, 0);
        assert!(!state.draining);
    }

    #[test]
    fn test_handle_control_ping() {
        let (supervisor, service) = IpcChannel::pair().unwrap();
        let mut state = ServiceState::default();

        handle_control(&service, &mut state, ControlMessage::Ping { seq: 99 }).unwrap();

        let response: Message = supervisor.recv().unwrap();
        assert!(matches!(response, Message::Control(ControlMessage::Pong { seq: 99, .. })));
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
    fn test_handle_message_audit_event() {
        let (client, service) = IpcChannel::pair().unwrap();
        let mut state = ServiceState::default();

        let event = Message::AuditEvent {
            timestamp: 1706140800,
            event_type: AuditEventType::SessionStart,
            user_id: Some("alice".to_string()),
            session_id: Some("sess123".to_string()),
            source_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            details: "SSH session started".to_string(),
        };
        handle_message(&service, &mut state, event).unwrap();

        assert_eq!(state.requests_processed, 1);

        let response: Message = client.recv().unwrap();
        if let Message::AuditAck { timestamp } = response {
            assert_eq!(timestamp, 1706140800);
        } else {
            panic!("Expected AuditAck");
        }
    }

    #[test]
    fn test_handle_message_session_recording() {
        let (_client, service) = IpcChannel::pair().unwrap();
        let mut state = ServiceState::default();

        let chunk = Message::SessionRecordingChunk {
            session_id: "sess123".to_string(),
            sequence: 1,
            data: vec![0; 1024],
        };
        handle_message(&service, &mut state, chunk).unwrap();

        assert_eq!(state.requests_processed, 1);
    }

    #[test]
    fn test_handle_message_control() {
        let (supervisor, service) = IpcChannel::pair().unwrap();
        let mut state = ServiceState::default();

        let msg = Message::Control(ControlMessage::Ping { seq: 11 });
        handle_message(&service, &mut state, msg).unwrap();

        let response: Message = supervisor.recv().unwrap();
        assert!(matches!(response, Message::Control(ControlMessage::Pong { seq: 11, .. })));
    }

    #[test]
    fn test_multiple_audit_events() {
        let (client, service) = IpcChannel::pair().unwrap();
        let mut state = ServiceState::default();

        for i in 0..5 {
            let event = Message::AuditEvent {
                timestamp: 1000 + i,
                event_type: AuditEventType::AuthSuccess,
                user_id: Some(format!("user{}", i)),
                session_id: None,
                source_ip: None,
                details: "Login".to_string(),
            };
            handle_message(&service, &mut state, event).unwrap();
        }

        assert_eq!(state.requests_processed, 5);

        for i in 0..5 {
            let response: Message = client.recv().unwrap();
            if let Message::AuditAck { timestamp } = response {
                assert_eq!(timestamp, 1000 + i);
            } else {
                panic!("Expected AuditAck");
            }
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
        let handle_ctrl_start = source.find("fn handle_control").expect("handle_control must exist");
        let handle_ctrl_source = &source[handle_ctrl_start..];
        assert!(
            handle_ctrl_source.contains("shutdown_requested = true"),
            "M-8/M-10: handle_control must set shutdown_requested = true on Shutdown"
        );
    }
}
