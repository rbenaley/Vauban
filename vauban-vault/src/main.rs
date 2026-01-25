//! Vauban Vault Service
//!
//! Handles:
//! - Secrets management
//! - Key rotation
//! - HSM integration
//! - Credential injection for proxies

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
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    info!("vauban-vault starting");

    match run_service() {
        Ok(()) => {
            info!("vauban-vault exiting normally");
            ExitCode::SUCCESS
        }
        Err(e) => {
            error!("vauban-vault error: {:#}", e);
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

    // TODO: Connect to HashiCorp Vault / HSM before entering sandbox
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

        Message::VaultGetSecret { request_id, path } => {
            info!("Vault get secret: {}", path);
            state.requests_processed += 1;

            // TODO: Actual secret retrieval from HSM/Vault
            let response = Message::VaultSecretResponse {
                request_id,
                data: Some(b"placeholder-secret".to_vec()),
            };
            channel.send(&response)?;
            Ok(())
        }

        Message::VaultGetCredential {
            request_id,
            asset_id,
            credential_type,
        } => {
            info!("Vault get credential: {} ({})", asset_id, credential_type);
            state.requests_processed += 1;

            // TODO: Actual credential retrieval
            let response = Message::VaultCredentialResponse {
                request_id,
                credential: Some(b"placeholder-credential".to_vec()),
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

        handle_control(&service, &mut state, ControlMessage::Ping { seq: 7 }).unwrap();

        let response: Message = supervisor.recv().unwrap();
        assert!(matches!(response, Message::Control(ControlMessage::Pong { seq: 7, .. })));
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
    fn test_handle_message_get_secret() {
        let (client, service) = IpcChannel::pair().unwrap();
        let mut state = ServiceState::default();

        let request = Message::VaultGetSecret {
            request_id: 1,
            path: "/secrets/db/password".to_string(),
        };
        handle_message(&service, &mut state, request).unwrap();

        assert_eq!(state.requests_processed, 1);

        let response: Message = client.recv().unwrap();
        if let Message::VaultSecretResponse { request_id, data } = response {
            assert_eq!(request_id, 1);
            assert!(data.is_some());
        } else {
            panic!("Expected VaultSecretResponse");
        }
    }

    #[test]
    fn test_handle_message_get_credential() {
        let (client, service) = IpcChannel::pair().unwrap();
        let mut state = ServiceState::default();

        let request = Message::VaultGetCredential {
            request_id: 2,
            asset_id: "server1".to_string(),
            credential_type: "ssh_key".to_string(),
        };
        handle_message(&service, &mut state, request).unwrap();

        assert_eq!(state.requests_processed, 1);

        let response: Message = client.recv().unwrap();
        if let Message::VaultCredentialResponse { request_id, credential } = response {
            assert_eq!(request_id, 2);
            assert!(credential.is_some());
        } else {
            panic!("Expected VaultCredentialResponse");
        }
    }

    #[test]
    fn test_handle_message_control() {
        let (supervisor, service) = IpcChannel::pair().unwrap();
        let mut state = ServiceState::default();

        let msg = Message::Control(ControlMessage::Ping { seq: 3 });
        handle_message(&service, &mut state, msg).unwrap();

        let response: Message = supervisor.recv().unwrap();
        assert!(matches!(response, Message::Control(ControlMessage::Pong { seq: 3, .. })));
    }
}
