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

    /// The target presented a certificate whose SPKI is not the pinned
    /// one. Typed, with no text: the pinning verifier reports it through
    /// a flag, not through the wording of the TLS error.
    #[error("RDP server certificate does not match the pinned one")]
    ServerCertificateMismatch,

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
    /// The closed-set code sent to vauban-web for this error. The text of
    /// the error (`to_string()`) can quote the target or the TLS stack and
    /// never leaves this process.
    ///
    /// EXHAUSTIVE match (no `_` arm): a new error does not compile until
    /// it has a code.
    pub const fn open_failure(&self) -> shared::messages::RdpOpenFailure {
        use shared::messages::RdpOpenFailure;
        match self {
            Self::ServerCertificateMismatch => RdpOpenFailure::ServerCertificateMismatch,
            Self::TlsUpgradeFailed(_) => RdpOpenFailure::TlsFailed,
            Self::ConnectionFailed(_) | Self::IoError(_) | Self::SessionClosed => {
                RdpOpenFailure::ConnectionFailed
            }
            Self::SessionFailed(_) => RdpOpenFailure::SessionFailed,
            // An NLA failure travels as `RdpSessionOpenFailed`, not here.
            Self::AuthenticationFailed { .. }
            | Self::SessionNotFound(_)
            | Self::SessionAlreadyExists(_)
            | Self::PngEncodingFailed(_) => RdpOpenFailure::Internal,
        }
    }

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
