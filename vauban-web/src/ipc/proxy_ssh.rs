//! IPC client for communication with vauban-proxy-ssh.
//!
//! Provides async methods to open SSH sessions, send terminal data,
//! and receive output from SSH sessions.

use crate::error::{AppError, AppResult};
use shared::ipc::IpcChannel;
use shared::messages::Message;
use std::collections::HashMap;
use std::io;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tokio::sync::{mpsc, oneshot, Mutex};
use tracing::{debug, error, info, warn};

/// Request to open an SSH session.
///
/// `Debug` is manually implemented to redact `password`, `private_key`, and
/// `passphrase` fields, preventing credential leaks in logs (H-4 / H-10).
#[derive(Clone)]
pub struct SshSessionOpenRequest {
    /// Unique session ID (UUID).
    pub session_id: String,
    /// Vauban user ID.
    pub user_id: String,
    /// Asset UUID.
    pub asset_id: String,
    /// Target hostname or IP.
    pub asset_host: String,
    /// SSH port.
    pub asset_port: u16,
    /// SSH username.
    pub username: String,
    /// Terminal width.
    pub terminal_cols: u16,
    /// Terminal height.
    pub terminal_rows: u16,
    /// Authentication type: "password" or "private_key".
    pub auth_type: String,
    /// Password for password authentication.
    pub password: Option<String>,
    /// PEM-encoded private key for key authentication.
    pub private_key: Option<String>,
    /// Passphrase for encrypted private key.
    pub passphrase: Option<String>,
}

impl std::fmt::Debug for SshSessionOpenRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshSessionOpenRequest")
            .field("session_id", &self.session_id)
            .field("user_id", &self.user_id)
            .field("asset_id", &self.asset_id)
            .field("asset_host", &self.asset_host)
            .field("asset_port", &self.asset_port)
            .field("username", &self.username)
            .field("terminal_cols", &self.terminal_cols)
            .field("terminal_rows", &self.terminal_rows)
            .field("auth_type", &self.auth_type)
            .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
            .field("private_key", &self.private_key.as_ref().map(|_| "[REDACTED]"))
            .field("passphrase", &self.passphrase.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

/// Response from opening an SSH session.
#[derive(Debug, Clone)]
pub struct SshSessionOpened {
    /// Request ID for correlation.
    pub request_id: u64,
    /// Session ID.
    pub session_id: String,
    /// Whether the session was opened successfully.
    pub success: bool,
    /// Error message if failed.
    pub error: Option<String>,
}

/// Async client for communicating with vauban-proxy-ssh.
pub struct ProxySshClient {
    /// Underlying IPC channel.
    channel: IpcChannel,
    /// Async file descriptor for reading.
    read_async_fd: AsyncFd<RawFd>,
    /// Next request ID.
    next_request_id: AtomicU64,
    /// Pending requests waiting for responses.
    pending_requests: Mutex<HashMap<u64, oneshot::Sender<SshSessionOpened>>>,
    /// Per-session data senders: session_id -> Sender.
    /// Each WebSocket subscribes to its session's channel.
    session_data_senders: Mutex<HashMap<String, mpsc::Sender<Vec<u8>>>>,
    /// Per-session data receivers waiting to be claimed by WebSocket.
    /// Created during open_session, taken by subscribe_session.
    session_data_receivers: Mutex<HashMap<String, mpsc::Receiver<Vec<u8>>>>,
}

impl ProxySshClient {
    /// Create a new SSH proxy client.
    ///
    /// The file descriptors should be passed by the supervisor.
    pub fn new(read_fd: RawFd, write_fd: RawFd) -> io::Result<Arc<Self>> {
        // Create IPC channel
        let channel = unsafe { IpcChannel::from_raw_fds(read_fd, write_fd) };

        // Set read fd to non-blocking
        set_nonblocking(read_fd)?;

        let read_async_fd = AsyncFd::new(read_fd)?;

        Ok(Arc::new(Self {
            channel,
            read_async_fd,
            next_request_id: AtomicU64::new(1),
            pending_requests: Mutex::new(HashMap::new()),
            session_data_senders: Mutex::new(HashMap::new()),
            session_data_receivers: Mutex::new(HashMap::new()),
        }))
    }

    /// Subscribe to SSH data for a specific session.
    ///
    /// Returns a receiver that will receive data from the SSH session.
    /// If the session was opened (via `open_session`), the receiver was pre-created
    /// and buffered data will be available. Otherwise, a new channel is created.
    /// Call `unsubscribe_session` when the WebSocket disconnects.
    pub async fn subscribe_session(&self, session_id: &str) -> mpsc::Receiver<Vec<u8>> {
        // First, try to take the pre-created receiver (from open_session)
        let existing_rx = self
            .session_data_receivers
            .lock()
            .await
            .remove(session_id);

        if let Some(rx) = existing_rx {
            debug!(session_id = %session_id, "WebSocket claimed pre-created SSH data channel");
            return rx;
        }

        // Fallback: create a new channel (shouldn't happen in normal flow)
        let (tx, rx) = mpsc::channel(256);
        self.session_data_senders
            .lock()
            .await
            .insert(session_id.to_string(), tx);
        debug!(session_id = %session_id, "WebSocket subscribed to SSH session (new channel)");
        rx
    }

    /// Unsubscribe from SSH data for a session.
    ///
    /// Should be called when the WebSocket disconnects.
    pub async fn unsubscribe_session(&self, session_id: &str) {
        self.session_data_senders
            .lock()
            .await
            .remove(session_id);
        debug!(session_id = %session_id, "WebSocket unsubscribed from SSH session");
    }

    /// Request to open a new SSH session.
    pub async fn open_session(&self, request: SshSessionOpenRequest) -> AppResult<SshSessionOpened> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::SeqCst);
        let session_id = request.session_id.clone();

        debug!(
            request_id = request_id,
            session_id = %session_id,
            host = %request.asset_host,
            "Opening SSH session"
        );

        // Pre-create the data channel BEFORE sending the request.
        // This ensures SSH output is buffered even if WebSocket isn't connected yet.
        let (data_tx, data_rx) = mpsc::channel(256);
        {
            let mut senders = self.session_data_senders.lock().await;
            senders.insert(session_id.clone(), data_tx);
        }
        {
            let mut receivers = self.session_data_receivers.lock().await;
            receivers.insert(session_id.clone(), data_rx);
        }

        // Create response channel
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.pending_requests.lock().await;
            pending.insert(request_id, tx);
        }

        // Send request
        let msg = Message::SshSessionOpen {
            request_id,
            session_id,
            user_id: request.user_id,
            asset_id: request.asset_id,
            asset_host: request.asset_host,
            asset_port: request.asset_port,
            username: request.username,
            terminal_cols: request.terminal_cols,
            terminal_rows: request.terminal_rows,
            auth_type: request.auth_type,
            password: request.password,
            private_key: request.private_key,
            passphrase: request.passphrase,
        };

        self.channel
            .send(&msg)
            .map_err(|e| AppError::Ipc(format!("IPC send failed: {}", e)))?;

        // Wait for response with timeout
        match tokio::time::timeout(std::time::Duration::from_secs(30), rx).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => {
                // Channel was dropped (shouldn't happen)
                Err(AppError::Ipc("Response channel dropped".to_string()))
            }
            Err(_) => {
                // Timeout
                let mut pending = self.pending_requests.lock().await;
                pending.remove(&request_id);
                Err(AppError::Ipc("SSH session open timeout".to_string()))
            }
        }
    }

    /// Send terminal input data to a session.
    pub fn send_data(&self, session_id: &str, data: &[u8]) -> AppResult<()> {
        let msg = Message::SshData {
            session_id: session_id.to_string(),
            data: data.to_vec(),
        };

        self.channel
            .send(&msg)
            .map_err(|e| AppError::Ipc(format!("IPC send failed: {}", e)))
    }

    /// Send terminal resize event.
    pub fn resize(&self, session_id: &str, cols: u16, rows: u16) -> AppResult<()> {
        let msg = Message::SshResize {
            session_id: session_id.to_string(),
            cols,
            rows,
        };

        self.channel
            .send(&msg)
            .map_err(|e| AppError::Ipc(format!("IPC send failed: {}", e)))
    }

    /// Close an SSH session.
    pub fn close_session(&self, session_id: &str) -> AppResult<()> {
        let msg = Message::SshSessionClose {
            session_id: session_id.to_string(),
        };

        self.channel
            .send(&msg)
            .map_err(|e| AppError::Ipc(format!("IPC send failed: {}", e)))
    }

    /// Process incoming messages from the proxy.
    ///
    /// This should be called in a loop from a dedicated task.
    pub async fn process_incoming(&self) -> AppResult<()> {
        loop {
            // Wait for the fd to be readable
            let mut guard = self
                .read_async_fd
                .ready(Interest::READABLE)
                .await
                .map_err(|e| AppError::Ipc(format!("AsyncFd ready failed: {}", e)))?;

            // Try to receive messages
            loop {
                match self.channel.try_recv() {
                    Ok(msg) => {
                        self.handle_message(msg).await;
                    }
                    Err(shared::ipc::IpcError::Io(ref e))
                        if e.kind() == io::ErrorKind::WouldBlock =>
                    {
                        // No more messages available
                        guard.clear_ready();
                        break;
                    }
                    Err(shared::ipc::IpcError::ConnectionClosed) => {
                        info!("SSH proxy IPC connection closed");
                        return Err(AppError::Ipc("IPC connection closed".to_string()));
                    }
                    Err(e) => {
                        error!(error = %e, "IPC receive error");
                        guard.clear_ready();
                        break;
                    }
                }
            }
        }
    }

    /// Handle an incoming message from the proxy.
    async fn handle_message(&self, msg: Message) {
        match msg {
            Message::SshSessionOpened {
                request_id,
                session_id,
                success,
                error,
            } => {
                debug!(
                    request_id = request_id,
                    session_id = %session_id,
                    success = success,
                    "SSH session opened response"
                );

                let response = SshSessionOpened {
                    request_id,
                    session_id,
                    success,
                    error,
                };

                // Find and notify the waiting request
                let mut pending = self.pending_requests.lock().await;
                if let Some(tx) = pending.remove(&request_id) {
                    let _ = tx.send(response);
                }
            }

            Message::SshData { session_id, data } => {
                // Forward data to the session's subscribed WebSocket
                let senders = self.session_data_senders.lock().await;
                if let Some(tx) = senders.get(&session_id) {
                    if tx.send(data).await.is_err() {
                        warn!(session_id = %session_id, "Failed to forward SSH data, WebSocket dropped");
                    }
                } else {
                    debug!(session_id = %session_id, "SSH data received but no WebSocket subscribed");
                }
            }

            _ => {
                debug!(?msg, "Ignoring unexpected message from proxy");
            }
        }
    }
}

/// Set a file descriptor to non-blocking mode.
fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    use libc::{fcntl, F_GETFL, F_SETFL, O_NONBLOCK};

    // SAFETY: We're calling fcntl with valid arguments on a valid fd.
    unsafe {
        let flags = fcntl(fd, F_GETFL);
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::io::AsRawFd;

    /// Create a test SSH session open request with default auth fields.
    fn make_test_request(session_id: &str, host: &str, port: u16) -> SshSessionOpenRequest {
        SshSessionOpenRequest {
            session_id: session_id.to_string(),
            user_id: "user".to_string(),
            asset_id: "asset".to_string(),
            asset_host: host.to_string(),
            asset_port: port,
            username: "admin".to_string(),
            terminal_cols: 80,
            terminal_rows: 24,
            auth_type: "password".to_string(),
            password: Some("test-password".to_string()),
            private_key: None,
            passphrase: None,
        }
    }

    // ==================== SshSessionOpenRequest Tests ====================

    #[test]
    fn test_ssh_session_open_request() {
        let request = make_test_request("sess-123", "192.168.1.100", 22);
        assert_eq!(request.session_id, "sess-123");
        assert_eq!(request.asset_port, 22);
        assert_eq!(request.auth_type, "password");
    }

    #[test]
    fn test_ssh_session_open_request_clone() {
        let mut request = make_test_request("clone-test", "10.0.0.1", 2222);
        request.username = "root".to_string();
        request.terminal_cols = 120;
        request.terminal_rows = 40;

        let cloned = request.clone();

        assert_eq!(request.session_id, cloned.session_id);
        assert_eq!(request.asset_host, cloned.asset_host);
        assert_eq!(request.asset_port, cloned.asset_port);
        assert_eq!(request.terminal_cols, cloned.terminal_cols);
    }

    #[test]
    fn test_ssh_session_open_request_debug_redacts_secrets() {
        let mut request = make_test_request("debug-sess", "host.local", 22);
        request.password = Some("super-secret-password".to_string());
        request.private_key = Some("-----BEGIN RSA PRIVATE KEY-----".to_string());
        request.passphrase = Some("my-passphrase".to_string());

        let debug_str = format!("{:?}", request);

        assert!(debug_str.contains("SshSessionOpenRequest"));
        assert!(debug_str.contains("debug-sess"));
        assert!(debug_str.contains("host.local"));
        // Secrets MUST be redacted (H-4 / H-10)
        assert!(
            !debug_str.contains("super-secret-password"),
            "Password must not appear in Debug output"
        );
        assert!(
            !debug_str.contains("BEGIN RSA PRIVATE KEY"),
            "Private key must not appear in Debug output"
        );
        assert!(
            !debug_str.contains("my-passphrase"),
            "Passphrase must not appear in Debug output"
        );
        assert!(debug_str.contains("[REDACTED]"));
    }

    #[test]
    fn test_ssh_session_open_request_ipv6_host() {
        let request = make_test_request("ipv6-sess", "2001:db8::1", 22);
        assert_eq!(request.asset_host, "2001:db8::1");
    }

    #[test]
    fn test_ssh_session_open_request_alternate_port() {
        let request = make_test_request("alt-port", "server.local", 8022);
        assert_eq!(request.asset_port, 8022);
    }

    #[test]
    fn test_ssh_session_open_request_large_terminal() {
        let mut request = make_test_request("large", "host", 22);
        request.terminal_cols = 300;
        request.terminal_rows = 100;

        assert_eq!(request.terminal_cols, 300);
        assert_eq!(request.terminal_rows, 100);
    }

    #[test]
    fn test_ssh_session_open_request_private_key_auth() {
        let request = SshSessionOpenRequest {
            session_id: "key-auth".to_string(),
            user_id: "user".to_string(),
            asset_id: "asset".to_string(),
            asset_host: "host".to_string(),
            asset_port: 22,
            username: "admin".to_string(),
            terminal_cols: 80,
            terminal_rows: 24,
            auth_type: "private_key".to_string(),
            password: None,
            private_key: Some("-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----".to_string()),
            passphrase: Some("key-passphrase".to_string()),
        };

        assert_eq!(request.auth_type, "private_key");
        assert!(request.private_key.is_some());
        assert!(request.passphrase.is_some());
    }

    // ==================== SshSessionOpened Tests ====================

    #[test]
    fn test_ssh_session_opened_success() {
        let response = SshSessionOpened {
            request_id: 1,
            session_id: "sess-123".to_string(),
            success: true,
            error: None,
        };
        assert!(response.success);
        assert!(response.error.is_none());
    }

    #[test]
    fn test_ssh_session_opened_failure() {
        let response = SshSessionOpened {
            request_id: 1,
            session_id: "sess-123".to_string(),
            success: false,
            error: Some("Connection refused".to_string()),
        };
        assert!(!response.success);
        assert_eq!(response.error.unwrap(), "Connection refused");
    }

    #[test]
    fn test_ssh_session_opened_clone() {
        let response = SshSessionOpened {
            request_id: 42,
            session_id: "clone-sess".to_string(),
            success: true,
            error: None,
        };

        let cloned = response.clone();

        assert_eq!(response.request_id, cloned.request_id);
        assert_eq!(response.session_id, cloned.session_id);
        assert_eq!(response.success, cloned.success);
    }

    #[test]
    fn test_ssh_session_opened_debug() {
        let response = SshSessionOpened {
            request_id: 999,
            session_id: "debug-resp".to_string(),
            success: false,
            error: Some("Auth failed".to_string()),
        };

        let debug_str = format!("{:?}", response);

        assert!(debug_str.contains("SshSessionOpened"));
        assert!(debug_str.contains("999"));
        assert!(debug_str.contains("Auth failed"));
    }

    #[test]
    fn test_ssh_session_opened_various_errors() {
        let errors = [
            "Connection refused",
            "Authentication failed",
            "Timeout",
            "Host key verification failed",
            "Permission denied",
        ];

        for error_msg in errors {
            let response = SshSessionOpened {
                request_id: 1,
                session_id: "test".to_string(),
                success: false,
                error: Some(error_msg.to_string()),
            };

            assert!(!response.success);
            assert_eq!(response.error.as_deref(), Some(error_msg));
        }
    }

    // ==================== set_nonblocking Tests ====================

    #[test]
    fn test_set_nonblocking() {
        // Create a pipe for testing
        let (read_fd, _write_fd) = nix::unistd::pipe().unwrap();

        // Set non-blocking
        let result = set_nonblocking(read_fd.as_raw_fd());
        assert!(result.is_ok());

        // Verify it's non-blocking
        use libc::{fcntl, F_GETFL, O_NONBLOCK};
        let flags = unsafe { fcntl(read_fd.as_raw_fd(), F_GETFL) };
        assert!(flags & O_NONBLOCK != 0);
    }

    #[test]
    fn test_set_nonblocking_preserves_flags() {
        // Create a pipe for testing
        let (read_fd, _write_fd) = nix::unistd::pipe().unwrap();

        use libc::{fcntl, F_GETFL, O_NONBLOCK};

        // Get original flags
        let original_flags = unsafe { fcntl(read_fd.as_raw_fd(), F_GETFL) };

        // Set non-blocking
        set_nonblocking(read_fd.as_raw_fd()).unwrap();

        // Check flags
        let new_flags = unsafe { fcntl(read_fd.as_raw_fd(), F_GETFL) };
        assert_eq!(new_flags, original_flags | O_NONBLOCK);
    }

    #[test]
    fn test_set_nonblocking_idempotent() {
        // Create a pipe for testing
        let (read_fd, _write_fd) = nix::unistd::pipe().unwrap();

        // Set non-blocking twice
        set_nonblocking(read_fd.as_raw_fd()).unwrap();
        set_nonblocking(read_fd.as_raw_fd()).unwrap();

        // Verify it's still non-blocking
        use libc::{fcntl, F_GETFL, O_NONBLOCK};
        let flags = unsafe { fcntl(read_fd.as_raw_fd(), F_GETFL) };
        assert!(flags & O_NONBLOCK != 0);
    }

    // ==================== AtomicU64 Request ID Tests ====================

    #[test]
    fn test_request_id_counter_increments() {
        let counter = AtomicU64::new(1);

        let id1 = counter.fetch_add(1, Ordering::SeqCst);
        let id2 = counter.fetch_add(1, Ordering::SeqCst);
        let id3 = counter.fetch_add(1, Ordering::SeqCst);

        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(id3, 3);
    }

    #[test]
    fn test_request_id_counter_wraps() {
        let counter = AtomicU64::new(u64::MAX);

        let id1 = counter.fetch_add(1, Ordering::SeqCst);
        let id2 = counter.fetch_add(1, Ordering::SeqCst);

        assert_eq!(id1, u64::MAX);
        assert_eq!(id2, 0); // Wrapped around
    }
}
