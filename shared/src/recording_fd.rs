//! Proxy/audit-owned recording file FD leases via the supervisor SCM_RIGHTS broker.
//!
//! Tokio-free: works in the audit main loop and in async proxies (call from
//! `spawn_blocking` / a dedicated thread when the caller must not park a
//! tokio worker on `poll`/`recv`).
//!
//! Extracted from `vauban-audit`'s `request_file_from_supervisor` /
//! `recv_fd_timed` / `recv_from_supervisor_until` so SSH/RDP proxies and
//! audit share one broker client.

use std::fs::File;
use std::os::fd::{OwnedFd, RawFd};
use std::time::{Duration, Instant};

use thiserror::Error;
use tracing::warn;

use crate::ipc::{self, IpcChannel, IpcError};
use crate::messages::{ControlMessage, Message, ServiceStats};
use crate::recording_paths::validate_recording_file_relative_path;

/// Default supervisor broker wait for a `RecordingFileResponse` + SCM_RIGHTS.
///
/// Matches `vauban_audit::SUPERVISOR_BROKER_TIMEOUT_SECS` / `mfa_hol_budget`
/// (2 s) so a wedged broker cannot exhaust the web critical ACK budget.
/// Kept as a shared constant (not imported from audit) to avoid a circular
/// dependency — audit will migrate onto this module later.
pub const DEFAULT_BROKER_TIMEOUT: Duration = Duration::from_secs(2);

/// Errors from the recording FD broker client.
#[derive(Debug, Error)]
pub enum RecordingFdError {
    #[error("invalid recording path: {0}")]
    InvalidPath(String),

    #[error("supervisor broker reply timed out")]
    Timeout,

    #[error("recv_fd timed out waiting for SCM_RIGHTS")]
    FdTimeout,

    #[error("supervisor refused file creation: {0}")]
    Refused(String),

    #[error("IPC error waiting for supervisor broker reply: {0}")]
    Ipc(#[from] IpcError),

    #[error("internal: expected RecordingFileResponse, got {0}")]
    Unexpected(String),
}

/// Wait for a matching supervisor reply, answering Pings, until `deadline`.
///
/// Prevents an infinite `recv` when the peer is wedged or a version-skewed
/// supervisor drops an unrecognised request (bytes consumed, no response).
///
/// Non-matching messages are skipped with a `warn!` (except Pings, which
/// are answered with a default `Pong`).
pub fn recv_until(
    channel: &IpcChannel,
    deadline: Instant,
    mut pred: impl FnMut(&Message) -> bool,
) -> Result<Message, RecordingFdError> {
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(RecordingFdError::Timeout);
        }
        let remaining_ms = (deadline - now).as_millis().min(i32::MAX as u128) as i32;
        let ready = ipc::poll_readable(&[channel.read_fd()], remaining_ms.max(1))?;
        if ready.is_empty() {
            if Instant::now() >= deadline {
                return Err(RecordingFdError::Timeout);
            }
            continue;
        }
        match channel.recv() {
            Ok(Message::Control(ControlMessage::Ping { seq })) => {
                let _ = channel.send(&Message::Control(ControlMessage::Pong {
                    seq,
                    stats: ServiceStats::default(),
                }));
            }
            Ok(msg) if pred(&msg) => return Ok(msg),
            Ok(other) => {
                warn!(
                    msg = ?other,
                    "Unexpected message while waiting for supervisor broker reply"
                );
            }
            Err(e) => return Err(RecordingFdError::Ipc(e)),
        }
    }
}

/// Timed `recv_fd` so a missing SCM_RIGHTS payload cannot wedge the caller.
///
/// SAFETY INVARIANT: never falls through to a blocking `recv_fd` after the
/// deadline — the FD-passing socketpair is blocking by default, so a bare
/// `recv_fd` would park the thread (or tokio worker) indefinitely.
pub fn recv_fd_timed(socket_fd: RawFd, deadline: Instant) -> Result<OwnedFd, RecordingFdError> {
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(RecordingFdError::FdTimeout);
        }
        let remaining_ms = (deadline - now).as_millis().min(i32::MAX as u128) as i32;
        let ready = ipc::poll_readable(&[socket_fd], remaining_ms.max(1))?;
        if ready.is_empty() {
            if Instant::now() >= deadline {
                return Err(RecordingFdError::FdTimeout);
            }
            continue;
        }
        return ipc::recv_fd(socket_fd).map_err(RecordingFdError::Ipc);
    }
}

/// Lease a write-side recording file FD from the supervisor broker.
///
/// Sends `RecordingFileRequest { read_only: false }`, waits for a matching
/// `RecordingFileResponse` for `session_id` (skipping mismatches), then
/// receives the FD via SCM_RIGHTS and wraps it as a [`File`].
pub fn lease_write_fd(
    channel: &IpcChannel,
    fd_passing_socket: RawFd,
    session_id: &str,
    relative_path: &str,
    timeout: Duration,
) -> Result<File, RecordingFdError> {
    validate_recording_file_relative_path(relative_path, session_id)
        .map_err(RecordingFdError::InvalidPath)?;

    let deadline = Instant::now() + timeout;

    channel.send(&Message::RecordingFileRequest {
        request_id: 0,
        session_id: session_id.to_string(),
        relative_path: relative_path.to_string(),
        read_only: false,
    })?;

    loop {
        let msg = recv_until(channel, deadline, |m| {
            matches!(m, Message::RecordingFileResponse { .. })
        })?;
        match msg {
            Message::RecordingFileResponse {
                session_id: sid,
                success,
                error,
                ..
            } => {
                if sid != session_id {
                    warn!(
                        expected = session_id,
                        got = %sid,
                        "Mismatched RecordingFileResponse session_id"
                    );
                    continue;
                }
                if !success {
                    return Err(RecordingFdError::Refused(error.unwrap_or_default()));
                }
                let owned_fd = recv_fd_timed(fd_passing_socket, deadline)?;
                return Ok(File::from(owned_fd));
            }
            other => {
                return Err(RecordingFdError::Unexpected(format!("{other:?}")));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_broker_timeout_matches_mfa_hol_budget() {
        assert_eq!(DEFAULT_BROKER_TIMEOUT, Duration::from_secs(2));
    }

    #[test]
    fn recording_file_request_constructs_write_lease() {
        let session_id = "sess-abc";
        let relative_path = format!("2026/07/{session_id}/session.cast");
        let msg = Message::RecordingFileRequest {
            request_id: 0,
            session_id: session_id.to_string(),
            relative_path: relative_path.clone(),
            read_only: false,
        };
        match msg {
            Message::RecordingFileRequest {
                request_id,
                session_id: sid,
                relative_path: path,
                read_only,
            } => {
                assert_eq!(request_id, 0);
                assert_eq!(sid, session_id);
                assert_eq!(path, relative_path);
                assert!(!read_only);
            }
            other => panic!("expected RecordingFileRequest, got {other:?}"),
        }
    }

    #[test]
    fn lease_write_fd_rejects_path_traversal() {
        // We cannot call lease_write_fd without a live channel, but the
        // InvalidPath arm is exercised by the same validator the lease
        // path uses before any IPC send.
        let err = validate_recording_file_relative_path("../evil/cast", "sess")
            .expect_err("traversal must fail");
        let wrapped = RecordingFdError::InvalidPath(err);
        assert!(
            wrapped.to_string().contains("invalid recording path"),
            "display: {}",
            wrapped
        );
    }

    #[test]
    fn lease_write_fd_rejects_path_missing_session_id() {
        let err = validate_recording_file_relative_path("2026/07/other/session.cast", "sess-abc")
            .expect_err("session_id anchor required");
        let wrapped = RecordingFdError::InvalidPath(err);
        assert!(matches!(wrapped, RecordingFdError::InvalidPath(_)));
    }

    #[test]
    fn error_display_covers_timeout_variants() {
        assert_eq!(
            RecordingFdError::Timeout.to_string(),
            "supervisor broker reply timed out"
        );
        assert_eq!(
            RecordingFdError::FdTimeout.to_string(),
            "recv_fd timed out waiting for SCM_RIGHTS"
        );
        assert_eq!(
            RecordingFdError::Refused("disk full".into()).to_string(),
            "supervisor refused file creation: disk full"
        );
    }
}
