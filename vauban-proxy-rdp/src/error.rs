//! Error types for vauban-proxy-rdp.

use thiserror::Error;

/// Errors that can occur during RDP session operations.
#[derive(Debug, Error)]
pub enum SessionError {
    #[error("RDP connection failed: {0}")]
    ConnectionFailed(String),

    /// The NLA leg failed. `reason` is what leaves the process; `detail`
    /// is for this process's log only (it can quote text written by the
    /// KDC or the target).
    #[error("RDP authentication failed ({}): {detail}", reason.as_str())]
    AuthenticationFailed {
        reason: shared::messages::RdpAuthFailure,
        detail: String,
    },

    #[error("TLS upgrade failed: {0}")]
    TlsUpgradeFailed(String),

    #[error("RDP session error: {0}")]
    SessionFailed(String),

    #[error("Session not found: {0}")]
    SessionNotFound(String),

    #[error("Session already exists: {0}")]
    SessionAlreadyExists(String),

    #[error("Session I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Session closed")]
    SessionClosed,

    #[error("PNG encoding failed: {0}")]
    PngEncodingFailed(String),
}

impl SessionError {
    /// The classified reason, when this is an authentication failure.
    pub const fn auth_failure(&self) -> Option<shared::messages::RdpAuthFailure> {
        match self {
            Self::AuthenticationFailed { reason, .. } => Some(*reason),
            _ => None,
        }
    }
}

/// Errors that can occur during IPC operations.
#[derive(Debug, Error)]
pub enum IpcError {
    #[error("IPC send failed: {0}")]
    #[allow(dead_code)]
    SendFailed(String),

    #[error("IPC receive failed: {0}")]
    ReceiveFailed(String),

    #[error("IPC connection closed")]
    ConnectionClosed,

    #[error("IPC timeout")]
    #[allow(dead_code)]
    Timeout,

    #[error("IPC error: {0}")]
    SharedIpc(#[from] shared::ipc::IpcError),
}

pub type SessionResult<T> = Result<T, SessionError>;
pub type IpcResult<T> = Result<T, IpcError>;
