//! Error types for vauban-proxy-ssh.

use thiserror::Error;

/// Errors that can occur during SSH session operations.
#[derive(Debug, Error)]
pub enum SessionError {
    /// Failed to connect to SSH server.
    #[error("SSH connection failed: {0}")]
    ConnectionFailed(String),

    /// Authentication failed.
    #[error("SSH authentication failed: {0}")]
    AuthenticationFailed(String),

    /// Failed to open SSH channel.
    #[error("Failed to open SSH channel: {0}")]
    ChannelOpenFailed(String),

    /// Failed to request PTY.
    #[error("Failed to request PTY: {0}")]
    PtyRequestFailed(String),

    /// Failed to start shell.
    #[error("Failed to start shell: {0}")]
    ShellStartFailed(String),

    /// Session not found.
    #[error("Session not found: {0}")]
    SessionNotFound(String),

    /// Session already exists.
    #[error("Session already exists: {0}")]
    SessionAlreadyExists(String),

    /// I/O error during session.
    #[error("Session I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Session was closed.
    #[error("Session closed")]
    SessionClosed,

    /// Invalid credential format.
    #[error("Invalid credential: {0}")]
    #[allow(dead_code)] // Will be used when credential validation is implemented
    InvalidCredential(String),

    /// Failed to parse SSH key.
    #[error("Invalid SSH key: {0}")]
    InvalidKey(String),
}

/// Errors that can occur during IPC operations.
#[derive(Debug, Error)]
pub enum IpcError {
    /// Failed to send message.
    #[error("IPC send failed: {0}")]
    #[allow(dead_code)] // Will be used when IPC send error handling is implemented
    SendFailed(String),

    /// Failed to receive message.
    #[error("IPC receive failed: {0}")]
    ReceiveFailed(String),

    /// Connection closed.
    #[error("IPC connection closed")]
    ConnectionClosed,

    /// Timeout waiting for response.
    #[error("IPC timeout")]
    #[allow(dead_code)] // Will be used when IPC timeout handling is implemented
    Timeout,

    /// Underlying shared IPC error.
    #[error("IPC error: {0}")]
    SharedIpc(#[from] shared::ipc::IpcError),
}

/// Result type for session operations.
pub type SessionResult<T> = Result<T, SessionError>;

/// Result type for IPC operations.
pub type IpcResult<T> = Result<T, IpcError>;

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== SessionError Tests ====================

    #[test]
    fn test_session_error_display() {
        let err = SessionError::ConnectionFailed("timeout".to_string());
        assert_eq!(err.to_string(), "SSH connection failed: timeout");
    }

    #[test]
    fn test_session_error_authentication_failed() {
        let err = SessionError::AuthenticationFailed("invalid password".to_string());
        assert_eq!(
            err.to_string(),
            "SSH authentication failed: invalid password"
        );
    }

    #[test]
    fn test_session_error_not_found() {
        let err = SessionError::SessionNotFound("sess-123".to_string());
        assert_eq!(err.to_string(), "Session not found: sess-123");
    }

    #[test]
    fn test_session_error_channel_open_failed() {
        let err = SessionError::ChannelOpenFailed("channel rejected".to_string());
        assert_eq!(err.to_string(), "Failed to open SSH channel: channel rejected");
    }

    #[test]
    fn test_session_error_pty_request_failed() {
        let err = SessionError::PtyRequestFailed("pty not available".to_string());
        assert_eq!(err.to_string(), "Failed to request PTY: pty not available");
    }

    #[test]
    fn test_session_error_shell_start_failed() {
        let err = SessionError::ShellStartFailed("shell not found".to_string());
        assert_eq!(err.to_string(), "Failed to start shell: shell not found");
    }

    #[test]
    fn test_session_error_already_exists() {
        let err = SessionError::SessionAlreadyExists("sess-456".to_string());
        assert_eq!(err.to_string(), "Session already exists: sess-456");
    }

    #[test]
    fn test_session_error_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe closed");
        let err = SessionError::IoError(io_err);
        assert!(err.to_string().contains("I/O error"));
    }

    #[test]
    fn test_session_error_session_closed() {
        let err = SessionError::SessionClosed;
        assert_eq!(err.to_string(), "Session closed");
    }

    #[test]
    fn test_session_error_invalid_key() {
        let err = SessionError::InvalidKey("bad format".to_string());
        assert_eq!(err.to_string(), "Invalid SSH key: bad format");
    }

    #[test]
    fn test_session_error_debug() {
        let err = SessionError::ConnectionFailed("test".to_string());
        let debug = format!("{:?}", err);
        assert!(debug.contains("ConnectionFailed"));
    }

    // ==================== IpcError Tests ====================

    #[test]
    fn test_ipc_error_display() {
        let err = IpcError::SendFailed("pipe broken".to_string());
        assert_eq!(err.to_string(), "IPC send failed: pipe broken");
    }

    #[test]
    fn test_ipc_error_receive_failed() {
        let err = IpcError::ReceiveFailed("read error".to_string());
        assert_eq!(err.to_string(), "IPC receive failed: read error");
    }

    #[test]
    fn test_ipc_error_timeout() {
        let err = IpcError::Timeout;
        assert_eq!(err.to_string(), "IPC timeout");
    }

    #[test]
    fn test_ipc_error_connection_closed() {
        let err = IpcError::ConnectionClosed;
        assert_eq!(err.to_string(), "IPC connection closed");
    }

    #[test]
    fn test_ipc_error_debug() {
        let err = IpcError::Timeout;
        let debug = format!("{:?}", err);
        assert!(debug.contains("Timeout"));
    }

    // ==================== Result Type Tests ====================

    #[test]
    fn test_session_result_ok() {
        let result: SessionResult<i32> = Ok(42);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_session_result_err() {
        let result: SessionResult<i32> = Err(SessionError::SessionClosed);
        assert!(result.is_err());
    }

    #[test]
    fn test_ipc_result_ok() {
        let result: IpcResult<String> = Ok("success".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_ipc_result_err() {
        let result: IpcResult<String> = Err(IpcError::ConnectionClosed);
        assert!(result.is_err());
    }
}
