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

//! Vauban Audit Service
//!
//! Handles:
//! - WORM (Write Once Read Many) audit storage
//! - Session recording storage (fMP4 for RDP)
//! - Real-time alerts
//! - Audit log queries

mod fmp4_writer;
mod recording_manager;
mod ssh_recording_manager;

use anyhow::{Context, Result};
use recording_manager::RecordingManager;
use shared::capsicum;
use shared::ipc::{IpcChannel, poll_readable, recv_fd};
use shared::messages::{ControlMessage, Message, ServiceStats};
use ssh_recording_manager::SshRecordingManager;
use std::os::unix::io::{FromRawFd, IntoRawFd, RawFd};
use std::process::ExitCode;
use std::time::Instant;
use tracing::{debug, error, info, warn};

/// Service runtime state.
struct ServiceState {
    start_time: Instant,
    requests_processed: u64,
    requests_failed: u64,
    draining: bool,
    /// Flag set by ControlMessage::Shutdown to break the main loop
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

    let recording_enabled: bool = std::env::var("VAUBAN_RECORDING_ENABLED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(false);

    let fd_passing_socket: Option<RawFd> = std::env::var("VAUBAN_FD_PASSING_SOCKET")
        .ok()
        .and_then(|s| s.parse().ok());

    let proxy_rdp_fds: Option<(RawFd, RawFd)> = if recording_enabled {
        let r: Option<RawFd> = std::env::var("VAUBAN_PROXY_RDP_IPC_READ")
            .ok()
            .and_then(|s| s.parse().ok());
        let w: Option<RawFd> = std::env::var("VAUBAN_PROXY_RDP_IPC_WRITE")
            .ok()
            .and_then(|s| s.parse().ok());
        match (r, w) {
            (Some(r), Some(w)) => {
                info!("Proxy-RDP IPC channel available for recording");
                Some((r, w))
            }
            _ => {
                debug!("VAUBAN_PROXY_RDP_IPC_READ/WRITE not set (RDP recording disabled)");
                None
            }
        }
    } else {
        None
    };

    let proxy_ssh_fds: Option<(RawFd, RawFd)> = if recording_enabled {
        let r: Option<RawFd> = std::env::var("VAUBAN_PROXY_SSH_IPC_READ")
            .ok()
            .and_then(|s| s.parse().ok());
        let w: Option<RawFd> = std::env::var("VAUBAN_PROXY_SSH_IPC_WRITE")
            .ok()
            .and_then(|s| s.parse().ok());
        match (r, w) {
            (Some(r), Some(w)) => {
                info!("Proxy-SSH IPC channel available for recording");
                Some((r, w))
            }
            _ => {
                debug!("VAUBAN_PROXY_SSH_IPC_READ/WRITE not set (SSH recording disabled)");
                None
            }
        }
    } else {
        None
    };

    // SAFETY: We are the only thread at this point, no concurrent access.
    unsafe {
        std::env::remove_var("VAUBAN_IPC_READ");
        std::env::remove_var("VAUBAN_IPC_WRITE");
        std::env::remove_var("VAUBAN_RECORDING_ENABLED");
        std::env::remove_var("VAUBAN_FD_PASSING_SOCKET");
        std::env::remove_var("VAUBAN_PROXY_RDP_IPC_READ");
        std::env::remove_var("VAUBAN_PROXY_RDP_IPC_WRITE");
        std::env::remove_var("VAUBAN_PROXY_SSH_IPC_READ");
        std::env::remove_var("VAUBAN_PROXY_SSH_IPC_WRITE");
    }

    let channel = unsafe { IpcChannel::from_raw_fds(ipc_read_fd, ipc_write_fd) };

    let proxy_rdp_channel = proxy_rdp_fds.map(|(r, w)| unsafe { IpcChannel::from_raw_fds(r, w) });
    let proxy_ssh_channel = proxy_ssh_fds.map(|(r, w)| unsafe { IpcChannel::from_raw_fds(r, w) });

    info!("Resources opened, preparing to enter sandbox");

    let mut ipc_fds = vec![ipc_read_fd, ipc_write_fd];
    if let Some((r, w)) = proxy_rdp_fds {
        ipc_fds.push(r);
        ipc_fds.push(w);
    }
    if let Some((r, w)) = proxy_ssh_fds {
        ipc_fds.push(r);
        ipc_fds.push(w);
    }
    // The fd_passing socket needs fd_receiver_socket rights for SCM_RIGHTS
    if let Some(fd) = fd_passing_socket {
        ipc_fds.push(fd);
    }

    capsicum::setup_service_sandbox(&ipc_fds, None).context("Failed to setup sandbox")?;

    if recording_enabled {
        info!(
            fd_passing = fd_passing_socket.is_some(),
            "Entered Capsicum sandbox with recording enabled"
        );
    } else {
        info!("Entered Capsicum sandbox, starting main loop");
    }

    let mut state = ServiceState::default();

    let mut recording_mgr = if recording_enabled {
        Some(RecordingManager::new())
    } else {
        None
    };

    let mut ssh_recording_mgr = if recording_enabled {
        Some(SshRecordingManager::new())
    } else {
        None
    };

    main_loop(
        &channel,
        proxy_rdp_channel.as_ref(),
        proxy_ssh_channel.as_ref(),
        &mut state,
        &mut recording_mgr,
        &mut ssh_recording_mgr,
        fd_passing_socket,
    )
}

fn main_loop(
    channel: &IpcChannel,
    proxy_rdp_channel: Option<&IpcChannel>,
    proxy_ssh_channel: Option<&IpcChannel>,
    state: &mut ServiceState,
    recording_mgr: &mut Option<RecordingManager>,
    ssh_recording_mgr: &mut Option<SshRecordingManager>,
    fd_passing_socket: Option<RawFd>,
) -> Result<()> {
    let mut poll_fds: Vec<RawFd> = vec![channel.read_fd()];

    let rdp_poll_idx = if let Some(rdp_ch) = proxy_rdp_channel {
        poll_fds.push(rdp_ch.read_fd());
        Some(poll_fds.len() - 1)
    } else {
        None
    };

    let ssh_poll_idx = if let Some(ssh_ch) = proxy_ssh_channel {
        poll_fds.push(ssh_ch.read_fd());
        Some(poll_fds.len() - 1)
    } else {
        None
    };

    loop {
        // Check shutdown flag before blocking on poll.
        if state.shutdown_requested {
            info!("Shutdown flag set, exiting main loop to run destructors");
            return Ok(());
        }

        let ready = poll_readable(&poll_fds, 1000)?;

        if ready.is_empty() {
            continue;
        }

        // Index 0 is always the supervisor channel
        if ready.contains(&0) {
            match channel.recv() {
                Ok(msg) => {
                    if let Err(e) = handle_message(
                        channel,
                        state,
                        recording_mgr,
                        ssh_recording_mgr,
                        fd_passing_socket,
                        msg,
                    ) {
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

        // Proxy-RDP channel (if present)
        if let Some(idx) = rdp_poll_idx
            && ready.contains(&idx)
        {
            // SAFETY: rdp_poll_idx is only Some when proxy_rdp_channel is Some
            #[allow(clippy::unwrap_used)]
            let rdp_ch = proxy_rdp_channel.unwrap();
            match rdp_ch.recv() {
                Ok(msg) => {
                    if let Err(e) = handle_recording_message(
                        state,
                        recording_mgr,
                        channel,
                        fd_passing_socket,
                        msg,
                    ) {
                        warn!("Error handling recording message: {}", e);
                        state.requests_failed += 1;
                    }
                }
                Err(shared::ipc::IpcError::ConnectionClosed) => {
                    info!("Proxy-RDP IPC connection closed");
                }
                Err(e) => {
                    debug!(error = %e, "Proxy-RDP IPC receive error");
                }
            }
        }

        // Proxy-SSH channel (if present)
        if let Some(idx) = ssh_poll_idx
            && ready.contains(&idx)
        {
            // SAFETY: ssh_poll_idx is only Some when proxy_ssh_channel is Some
            #[allow(clippy::unwrap_used)]
            let ssh_ch = proxy_ssh_channel.unwrap();
            match ssh_ch.recv() {
                Ok(msg) => {
                    if let Err(e) = handle_ssh_recording_message(
                        state,
                        ssh_recording_mgr,
                        channel,
                        fd_passing_socket,
                        msg,
                    ) {
                        warn!("Error handling SSH recording message: {}", e);
                        state.requests_failed += 1;
                    }
                }
                Err(shared::ipc::IpcError::ConnectionClosed) => {
                    info!("Proxy-SSH IPC connection closed");
                }
                Err(e) => {
                    debug!(error = %e, "Proxy-SSH IPC receive error");
                }
            }
        }
    }
}

fn handle_message(
    channel: &IpcChannel,
    state: &mut ServiceState,
    recording_mgr: &mut Option<RecordingManager>,
    ssh_recording_mgr: &mut Option<SshRecordingManager>,
    fd_passing_socket: Option<RawFd>,
    msg: Message,
) -> Result<()> {
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

        // RDP recording messages can also arrive on the supervisor channel
        Message::RdpRecordingStart { .. }
        | Message::RdpVideoFrame { .. }
        | Message::RdpRecordingEnd { .. } => {
            handle_recording_message(state, recording_mgr, channel, fd_passing_socket, msg)
        }

        // SSH recording messages can also arrive on the supervisor channel
        Message::SshRecordingStart { .. }
        | Message::SshRecordingData { .. }
        | Message::SshRecordingEnd { .. } => {
            handle_ssh_recording_message(
                state,
                ssh_recording_mgr,
                channel,
                fd_passing_socket,
                msg,
            )
        }

        _ => {
            warn!("Unexpected message type");
            Ok(())
        }
    }
}

fn handle_recording_message(
    state: &mut ServiceState,
    recording_mgr: &mut Option<RecordingManager>,
    supervisor_channel: &IpcChannel,
    fd_passing_socket: Option<RawFd>,
    msg: Message,
) -> Result<()> {
    let Some(mgr) = recording_mgr.as_mut() else {
        debug!("Recording not enabled, ignoring recording message");
        return Ok(());
    };

    match msg {
        Message::RdpRecordingStart {
            session_id,
            width: _,
            height: _,
        } => {
            let relative_path = RecordingManager::compute_relative_path(&session_id);
            match request_file_from_supervisor(
                supervisor_channel,
                fd_passing_socket,
                &session_id,
                &relative_path,
            ) {
                Ok(file) => {
                    mgr.start_session(&session_id, file, relative_path);
                }
                Err(e) => {
                    error!(session_id, error = %e, "Failed to obtain recording file from supervisor");
                }
            }
            state.requests_processed += 1;
        }
        Message::RdpVideoFrame {
            session_id,
            timestamp_us,
            is_keyframe,
            width,
            height,
            data,
        } => {
            match mgr.handle_frame(&session_id, timestamp_us, is_keyframe, width, height, &data) {
                recording_manager::FrameResult::Processed => {}
                recording_manager::FrameResult::NewSegmentNeeded { relative_path } => {
                    match request_file_from_supervisor(
                        supervisor_channel,
                        fd_passing_socket,
                        &session_id,
                        &relative_path,
                    ) {
                        Ok(file) => mgr.provide_segment_file(&session_id, file),
                        Err(e) => {
                            error!(session_id, error = %e, "Failed to obtain new segment file");
                        }
                    }
                }
            }
            state.requests_processed += 1;
        }
        Message::RdpRecordingEnd { session_id } => {
            if let Some(result) = mgr.end_session(&session_id) {
                let meta_json = RecordingManager::serialize_meta_json(&result.segments);
                match request_file_from_supervisor(
                    supervisor_channel,
                    fd_passing_socket,
                    &session_id,
                    &result.meta_json_relative_path,
                ) {
                    Ok(meta_file) => {
                        use std::io::Write;
                        let mut meta_file = meta_file;
                        if let Err(e) = meta_file
                            .write_all(meta_json.as_bytes())
                            .and_then(|_| meta_file.flush())
                        {
                            error!(session_id, error = %e, "Failed to write meta.json");
                        } else {
                            info!(session_id, "meta.json written successfully");
                        }
                    }
                    Err(e) => {
                        error!(session_id, error = %e, "Failed to obtain meta.json file from supervisor");
                    }
                }
            }
            state.requests_processed += 1;
        }
        _ => {
            debug!("Non-recording message on recording handler");
        }
    }

    Ok(())
}

fn handle_ssh_recording_message(
    state: &mut ServiceState,
    ssh_recording_mgr: &mut Option<SshRecordingManager>,
    supervisor_channel: &IpcChannel,
    fd_passing_socket: Option<RawFd>,
    msg: Message,
) -> Result<()> {
    let Some(mgr) = ssh_recording_mgr.as_mut() else {
        debug!("SSH recording not enabled, ignoring SSH recording message");
        return Ok(());
    };

    match msg {
        Message::SshRecordingStart {
            session_id,
            width,
            height,
            asset_name,
            username,
        } => {
            let relative_path = SshRecordingManager::compute_relative_path(&session_id);
            match request_file_from_supervisor(
                supervisor_channel,
                fd_passing_socket,
                &session_id,
                &relative_path,
            ) {
                Ok(file) => {
                    mgr.start_session(
                        &session_id,
                        ssh_recording_manager::SshSessionStartParams {
                            file,
                            relative_path,
                            width,
                            height,
                            asset_name,
                            username,
                        },
                    );
                }
                Err(e) => {
                    error!(session_id, error = %e, "Failed to obtain SSH recording file from supervisor");
                }
            }
            state.requests_processed += 1;
        }
        Message::SshRecordingData {
            session_id,
            timestamp_us,
            event_type,
            data,
        } => {
            mgr.handle_data(&session_id, timestamp_us, event_type, &data);
            state.requests_processed += 1;
        }
        Message::SshRecordingEnd { session_id } => {
            if let Some(result) = mgr.end_session(&session_id) {
                let meta_json = SshRecordingManager::serialize_meta_json(&result);
                match request_file_from_supervisor(
                    supervisor_channel,
                    fd_passing_socket,
                    &session_id,
                    &result.meta_json_relative_path,
                ) {
                    Ok(meta_file) => {
                        use std::io::Write;
                        let mut meta_file = meta_file;
                        if let Err(e) = meta_file
                            .write_all(meta_json.as_bytes())
                            .and_then(|_| meta_file.flush())
                        {
                            error!(session_id, error = %e, "Failed to write SSH meta.json");
                        } else {
                            info!(session_id, "SSH meta.json written successfully");
                        }
                    }
                    Err(e) => {
                        error!(session_id, error = %e, "Failed to obtain SSH meta.json file from supervisor");
                    }
                }
            }
            state.requests_processed += 1;
        }
        _ => {
            debug!("Non-SSH-recording message on SSH recording handler");
        }
    }

    Ok(())
}

/// Request a file from the supervisor via IPC + SCM_RIGHTS.
///
/// Sends a `RecordingFileRequest`, waits for the `RecordingFileResponse`,
/// and receives the file descriptor on the fd_passing socket.
fn request_file_from_supervisor(
    channel: &IpcChannel,
    fd_passing_socket: Option<RawFd>,
    session_id: &str,
    relative_path: &str,
) -> Result<std::fs::File> {
    let fd_socket =
        fd_passing_socket.ok_or_else(|| anyhow::anyhow!("no fd_passing socket available"))?;

    channel.send(&Message::RecordingFileRequest {
        request_id: 0,
        session_id: session_id.to_string(),
        relative_path: relative_path.to_string(),
        read_only: false,
    })?;

    // Blocking wait for response. Handle Pings while waiting.
    loop {
        match channel.recv() {
            Ok(Message::RecordingFileResponse {
                request_id: _,
                session_id: sid,
                success,
                error,
            }) => {
                if sid != session_id {
                    warn!(expected = session_id, got = %sid, "Mismatched RecordingFileResponse session_id");
                    continue;
                }
                if !success {
                    return Err(anyhow::anyhow!(
                        "supervisor refused file creation: {}",
                        error.unwrap_or_default()
                    ));
                }
                let owned_fd =
                    recv_fd(fd_socket).map_err(|e| anyhow::anyhow!("recv_fd failed: {e}"))?;
                let file = unsafe { std::fs::File::from_raw_fd(owned_fd.into_raw_fd()) };
                return Ok(file);
            }
            Ok(Message::Control(ControlMessage::Ping { seq })) => {
                let stats = ServiceStats {
                    uptime_secs: 0,
                    requests_processed: 0,
                    requests_failed: 0,
                    active_connections: 0,
                    pending_requests: 0,
                };
                let _ = channel.send(&Message::Control(ControlMessage::Pong { seq, stats }));
            }
            Ok(other) => {
                debug!(msg = ?other, "Unexpected message while waiting for RecordingFileResponse");
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "IPC error waiting for RecordingFileResponse: {e}"
                ));
            }
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
            // Set flag instead of exit(0) so the main loop breaks
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
        assert!(matches!(
            response,
            Message::Control(ControlMessage::Pong { seq: 99, .. })
        ));
    }

    #[test]
    fn test_handle_control_drain() {
        let (supervisor, service) = IpcChannel::pair().unwrap();
        let mut state = ServiceState::default();

        handle_control(&service, &mut state, ControlMessage::Drain).unwrap();
        assert!(state.draining);

        let response: Message = supervisor.recv().unwrap();
        assert!(matches!(
            response,
            Message::Control(ControlMessage::DrainComplete { .. })
        ));
    }

    #[test]
    fn test_handle_message_audit_event() {
        let (client, service) = IpcChannel::pair().unwrap();
        let mut state = ServiceState::default();
        let mut recording_mgr = None;

        let event = Message::AuditEvent {
            timestamp: 1706140800,
            event_type: AuditEventType::SessionStart,
            user_id: Some("alice".to_string()),
            session_id: Some("sess123".to_string()),
            source_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            details: "SSH session started".to_string(),
        };
        handle_message(&service, &mut state, &mut recording_mgr, &mut None, None, event).unwrap();

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
        let mut recording_mgr = None;

        let chunk = Message::SessionRecordingChunk {
            session_id: "sess123".to_string(),
            sequence: 1,
            data: vec![0; 1024],
        };
        handle_message(&service, &mut state, &mut recording_mgr, &mut None, None, chunk).unwrap();

        assert_eq!(state.requests_processed, 1);
    }

    #[test]
    fn test_handle_message_control() {
        let (supervisor, service) = IpcChannel::pair().unwrap();
        let mut state = ServiceState::default();
        let mut recording_mgr = None;

        let msg = Message::Control(ControlMessage::Ping { seq: 11 });
        handle_message(&service, &mut state, &mut recording_mgr, &mut None, None, msg).unwrap();

        let response: Message = supervisor.recv().unwrap();
        assert!(matches!(
            response,
            Message::Control(ControlMessage::Pong { seq: 11, .. })
        ));
    }

    #[test]
    fn test_multiple_audit_events() {
        let (client, service) = IpcChannel::pair().unwrap();
        let mut state = ServiceState::default();
        let mut recording_mgr = None;

        for i in 0..5 {
            let event = Message::AuditEvent {
                timestamp: 1000 + i,
                event_type: AuditEventType::AuthSuccess,
                user_id: Some(format!("user{}", i)),
                session_id: None,
                source_ip: None,
                details: "Login".to_string(),
            };
            handle_message(&service, &mut state, &mut recording_mgr, &mut None, None, event)
                .unwrap();
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

    #[test]
    fn test_handle_recording_message_without_manager() {
        let (_sup, service) = IpcChannel::pair().unwrap();
        let mut state = ServiceState::default();
        let mut recording_mgr = None;

        let msg = Message::RdpRecordingStart {
            session_id: "test".to_string(),
            width: 1920,
            height: 1080,
        };
        handle_recording_message(&mut state, &mut recording_mgr, &service, None, msg).unwrap();
        assert_eq!(state.requests_processed, 0);
    }

    #[test]
    fn test_handle_recording_message_with_manager_via_fd_passing() {
        use shared::ipc::{send_fd, socketpair_for_fd_passing};
        use std::os::unix::io::AsRawFd;

        let dir = tempfile::tempdir().unwrap();
        let (supervisor_channel, audit_channel) = IpcChannel::pair().unwrap();
        let (supervisor_fd_sock, audit_fd_sock) = socketpair_for_fd_passing().unwrap();

        let audit_fd_sock_raw = audit_fd_sock.as_raw_fd();

        let mut state = ServiceState::default();
        let mut recording_mgr = Some(RecordingManager::new());

        // Simulate supervisor in a background thread
        let dir_path = dir.path().to_path_buf();
        let handle = std::thread::spawn(move || {
            let msg = supervisor_channel.recv().unwrap();
            if let Message::RecordingFileRequest {
                request_id,
                session_id,
                relative_path,
                ..
            } = msg
            {
                let full_path = dir_path.join(&relative_path);
                if let Some(parent) = full_path.parent() {
                    std::fs::create_dir_all(parent).unwrap();
                }
                let file = std::fs::File::create(&full_path).unwrap();
                send_fd(supervisor_fd_sock.as_raw_fd(), file.as_raw_fd()).unwrap();
                supervisor_channel
                    .send(&Message::RecordingFileResponse {
                        request_id,
                        session_id,
                        success: true,
                        error: None,
                    })
                    .unwrap();
            } else {
                panic!("Expected RecordingFileRequest");
            }
        });

        let msg = Message::RdpRecordingStart {
            session_id: "rec-test".to_string(),
            width: 1920,
            height: 1080,
        };
        handle_recording_message(
            &mut state,
            &mut recording_mgr,
            &audit_channel,
            Some(audit_fd_sock_raw),
            msg,
        )
        .unwrap();
        assert_eq!(state.requests_processed, 1);

        handle.join().unwrap();
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
        let main_loop_start = source.find("fn main_loop").expect("main_loop must exist");
        let main_loop_source = &source[main_loop_start..];
        assert!(
            main_loop_source.contains("shutdown_requested"),
            "main_loop must check shutdown_requested flag"
        );
    }

    #[test]
    fn test_handle_control_sets_shutdown_flag() {
        let source = prod_source();
        let handle_ctrl_start = source
            .find("fn handle_control")
            .expect("handle_control must exist");
        let handle_ctrl_source = &source[handle_ctrl_start..];
        assert!(
            handle_ctrl_source.contains("shutdown_requested = true"),
            "handle_control must set shutdown_requested = true on Shutdown"
        );
    }

    // ==================== SSH Recording Integration Tests ====================

    #[test]
    fn test_handle_ssh_recording_message_without_manager() {
        let (_sup, service) = IpcChannel::pair().unwrap();
        let mut state = ServiceState::default();
        let mut ssh_mgr = None;

        let msg = Message::SshRecordingStart {
            session_id: "test".to_string(),
            width: 80,
            height: 24,
            asset_name: "host".to_string(),
            username: "user".to_string(),
        };
        handle_ssh_recording_message(&mut state, &mut ssh_mgr, &service, None, msg).unwrap();
        assert_eq!(state.requests_processed, 0);
    }

    #[test]
    fn test_handle_ssh_recording_full_ipc_flow() {
        use shared::ipc::{send_fd, socketpair_for_fd_passing};
        use shared::messages::SshRecordingEvent;
        use std::os::unix::io::AsRawFd;

        let dir = tempfile::tempdir().unwrap();
        let (supervisor_channel, audit_channel) = IpcChannel::pair().unwrap();
        let (supervisor_fd_sock, audit_fd_sock) = socketpair_for_fd_passing().unwrap();

        let audit_fd_sock_raw = audit_fd_sock.as_raw_fd();

        let mut state = ServiceState::default();
        let mut ssh_mgr = Some(SshRecordingManager::new());

        let dir_path = dir.path().to_path_buf();

        // Supervisor thread: handles 2 file requests (session.cast + meta.json)
        let handle = std::thread::spawn(move || {
            for _ in 0..2 {
                let msg = supervisor_channel.recv().unwrap();
                if let Message::RecordingFileRequest {
                    request_id,
                    session_id,
                    relative_path,
                    ..
                } = msg
                {
                    let full_path = dir_path.join(&relative_path);
                    if let Some(parent) = full_path.parent() {
                        std::fs::create_dir_all(parent).unwrap();
                    }
                    let file = std::fs::File::create(&full_path).unwrap();
                    send_fd(supervisor_fd_sock.as_raw_fd(), file.as_raw_fd()).unwrap();
                    supervisor_channel
                        .send(&Message::RecordingFileResponse {
                            request_id,
                            session_id,
                            success: true,
                            error: None,
                        })
                        .unwrap();
                } else {
                    panic!("Expected RecordingFileRequest, got {:?}", msg);
                }
            }
        });

        // Start SSH recording
        handle_ssh_recording_message(
            &mut state,
            &mut ssh_mgr,
            &audit_channel,
            Some(audit_fd_sock_raw),
            Message::SshRecordingStart {
                session_id: "ssh-ipc-test".to_string(),
                width: 120,
                height: 40,
                asset_name: "prod-server".to_string(),
                username: "admin".to_string(),
            },
        )
        .unwrap();
        assert_eq!(state.requests_processed, 1);

        // Send data events
        handle_ssh_recording_message(
            &mut state,
            &mut ssh_mgr,
            &audit_channel,
            Some(audit_fd_sock_raw),
            Message::SshRecordingData {
                session_id: "ssh-ipc-test".to_string(),
                timestamp_us: 0,
                event_type: SshRecordingEvent::Output,
                data: b"$ ".to_vec(),
            },
        )
        .unwrap();

        handle_ssh_recording_message(
            &mut state,
            &mut ssh_mgr,
            &audit_channel,
            Some(audit_fd_sock_raw),
            Message::SshRecordingData {
                session_id: "ssh-ipc-test".to_string(),
                timestamp_us: 500_000,
                event_type: SshRecordingEvent::Input,
                data: b"ls\r".to_vec(),
            },
        )
        .unwrap();

        handle_ssh_recording_message(
            &mut state,
            &mut ssh_mgr,
            &audit_channel,
            Some(audit_fd_sock_raw),
            Message::SshRecordingData {
                session_id: "ssh-ipc-test".to_string(),
                timestamp_us: 1_000_000,
                event_type: SshRecordingEvent::Output,
                data: b"file1  file2\r\n".to_vec(),
            },
        )
        .unwrap();

        // End recording (triggers meta.json write)
        handle_ssh_recording_message(
            &mut state,
            &mut ssh_mgr,
            &audit_channel,
            Some(audit_fd_sock_raw),
            Message::SshRecordingEnd {
                session_id: "ssh-ipc-test".to_string(),
            },
        )
        .unwrap();

        handle.join().unwrap();

        // Verify .cast file is valid asciicast v2
        let cast_files: Vec<_> = walkdir(dir.path(), "session.cast");
        assert_eq!(cast_files.len(), 1, "Exactly one session.cast file");

        let cast_content = std::fs::read_to_string(&cast_files[0]).unwrap();
        let lines: Vec<&str> = cast_content.lines().collect();
        assert!(lines.len() >= 4, "Header + 3 events minimum");

        // Verify header
        let header: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(header["version"], 2);
        assert_eq!(header["width"], 120);
        assert_eq!(header["height"], 40);

        // Verify events are valid JSON arrays
        for line in &lines[1..] {
            let event: serde_json::Value = serde_json::from_str(line).unwrap();
            assert!(event.is_array(), "Event must be a JSON array");
            assert_eq!(event.as_array().unwrap().len(), 3, "Event must have 3 elements");
        }

        // Verify meta.json exists and is valid
        let meta_files: Vec<_> = walkdir(dir.path(), "meta.json");
        assert_eq!(meta_files.len(), 1, "Exactly one meta.json file");

        let meta_content = std::fs::read_to_string(&meta_files[0]).unwrap();
        let meta: serde_json::Value = serde_json::from_str(&meta_content).unwrap();
        assert_eq!(meta["format"], "asciicast-v2");
        assert!(meta["blake3_hex"].as_str().unwrap().len() == 64);
        assert_eq!(meta["total_events"], 3);
        assert_eq!(meta["width"], 120);
        assert_eq!(meta["height"], 40);
    }

    fn walkdir(root: &std::path::Path, filename: &str) -> Vec<std::path::PathBuf> {
        let mut results = Vec::new();
        fn visit(dir: &std::path::Path, filename: &str, results: &mut Vec<std::path::PathBuf>) {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        visit(&path, filename, results);
                    } else if path.file_name().and_then(|n| n.to_str()) == Some(filename) {
                        results.push(path);
                    }
                }
            }
        }
        visit(root, filename, &mut results);
        results
    }

    // ==================== SSH Recording Structural Tests ====================

    #[test]
    fn test_ssh_recording_handler_exists() {
        let source = prod_source();
        assert!(
            source.contains("fn handle_ssh_recording_message"),
            "handle_ssh_recording_message function must exist"
        );
    }

    #[test]
    fn test_ssh_recording_main_loop_polls_ssh_channel() {
        let source = prod_source();
        let main_loop = source
            .find("fn main_loop")
            .expect("main_loop must exist");
        let main_loop_source = &source[main_loop..];
        assert!(
            main_loop_source.contains("ssh_poll_idx"),
            "main_loop must poll the SSH recording channel"
        );
    }

    #[test]
    fn test_ssh_recording_env_vars_cleaned() {
        let source = prod_source();
        assert!(
            source.contains("remove_var(\"VAUBAN_PROXY_SSH_IPC_READ\")"),
            "SSH IPC env vars must be cleaned up"
        );
        assert!(
            source.contains("remove_var(\"VAUBAN_PROXY_SSH_IPC_WRITE\")"),
            "SSH IPC env vars must be cleaned up"
        );
    }
}
