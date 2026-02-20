//! IPC client for communication with vauban-proxy-rdp.
//!
//! Provides async methods to open RDP sessions, send input events,
//! and receive display updates from RDP sessions.

use crate::error::{AppError, AppResult};
use secrecy::{ExposeSecret, SecretString};
use shared::ipc::IpcChannel;
use shared::messages::{Message, RdpInputEvent, SensitiveString};
use std::collections::HashMap;
use std::io;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tokio::sync::{mpsc, oneshot, Mutex};
use tracing::{debug, error, info, warn};

/// Request to open an RDP session.
#[derive(Clone)]
pub struct RdpSessionOpenRequest {
    pub session_id: String,
    pub user_id: String,
    pub asset_id: String,
    pub asset_host: String,
    pub asset_port: u16,
    pub username: String,
    pub password: Option<SecretString>,
    pub domain: Option<String>,
    pub desktop_width: u16,
    pub desktop_height: u16,
}

impl std::fmt::Debug for RdpSessionOpenRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RdpSessionOpenRequest")
            .field("session_id", &self.session_id)
            .field("user_id", &self.user_id)
            .field("asset_id", &self.asset_id)
            .field("asset_host", &self.asset_host)
            .field("asset_port", &self.asset_port)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
            .field("domain", &self.domain)
            .field("desktop_width", &self.desktop_width)
            .field("desktop_height", &self.desktop_height)
            .finish()
    }
}

/// Response from opening an RDP session.
#[derive(Debug, Clone)]
pub struct RdpSessionOpened {
    pub request_id: u64,
    pub session_id: String,
    pub success: bool,
    pub desktop_width: u16,
    pub desktop_height: u16,
    pub error: Option<String>,
}

/// Display update received from RDP session (PNG-encoded region).
#[derive(Debug)]
pub struct RdpDisplayUpdate {
    pub x: u16,
    pub y: u16,
    pub width: u16,
    pub height: u16,
    pub png_data: Vec<u8>,
}

/// Async client for communicating with vauban-proxy-rdp.
pub struct ProxyRdpClient {
    channel: IpcChannel,
    read_async_fd: AsyncFd<RawFd>,
    next_request_id: AtomicU64,
    pending_requests: Mutex<HashMap<u64, oneshot::Sender<RdpSessionOpened>>>,
    /// Per-session display update senders: session_id -> Sender.
    session_display_senders: Mutex<HashMap<String, mpsc::Sender<RdpDisplayUpdate>>>,
    /// Pre-created receivers waiting to be claimed by WebSocket.
    session_display_receivers: Mutex<HashMap<String, mpsc::Receiver<RdpDisplayUpdate>>>,
}

impl ProxyRdpClient {
    pub fn new(read_fd: RawFd, write_fd: RawFd) -> io::Result<Arc<Self>> {
        let channel = unsafe { IpcChannel::from_raw_fds(read_fd, write_fd) };
        set_nonblocking(read_fd)?;
        let read_async_fd = AsyncFd::new(read_fd)?;

        Ok(Arc::new(Self {
            channel,
            read_async_fd,
            next_request_id: AtomicU64::new(1),
            pending_requests: Mutex::new(HashMap::new()),
            session_display_senders: Mutex::new(HashMap::new()),
            session_display_receivers: Mutex::new(HashMap::new()),
        }))
    }

    /// Subscribe to display updates for an RDP session.
    pub async fn subscribe_session(&self, session_id: &str) -> mpsc::Receiver<RdpDisplayUpdate> {
        let existing_rx = self
            .session_display_receivers
            .lock()
            .await
            .remove(session_id);

        if let Some(rx) = existing_rx {
            debug!(session_id = %session_id, "WebSocket claimed pre-created RDP display channel");
            return rx;
        }

        let (tx, rx) = mpsc::channel(256);
        self.session_display_senders
            .lock()
            .await
            .insert(session_id.to_string(), tx);
        debug!(session_id = %session_id, "WebSocket subscribed to RDP session (new channel)");
        rx
    }

    /// Unsubscribe from display updates for a session.
    pub async fn unsubscribe_session(&self, session_id: &str) {
        self.session_display_senders
            .lock()
            .await
            .remove(session_id);
        debug!(session_id = %session_id, "WebSocket unsubscribed from RDP session");
    }

    /// Request to open a new RDP session.
    pub async fn open_session(
        &self,
        request: RdpSessionOpenRequest,
    ) -> AppResult<RdpSessionOpened> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::SeqCst);
        let session_id = request.session_id.clone();

        debug!(
            request_id = request_id,
            session_id = %session_id,
            host = %request.asset_host,
            "Opening RDP session"
        );

        // Pre-create the display channel
        let (display_tx, display_rx) = mpsc::channel(256);
        {
            let mut senders = self.session_display_senders.lock().await;
            senders.insert(session_id.clone(), display_tx);
        }
        {
            let mut receivers = self.session_display_receivers.lock().await;
            receivers.insert(session_id.clone(), display_rx);
        }

        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.pending_requests.lock().await;
            pending.insert(request_id, tx);
        }

        let msg = Message::RdpSessionOpen {
            request_id,
            session_id,
            user_id: request.user_id,
            asset_id: request.asset_id,
            asset_host: request.asset_host,
            asset_port: request.asset_port,
            username: request.username,
            password: request
                .password
                .map(|s| SensitiveString::new(s.expose_secret().to_string())),
            domain: request.domain,
            desktop_width: request.desktop_width,
            desktop_height: request.desktop_height,
        };

        self.channel
            .send(&msg)
            .map_err(|e| AppError::Ipc(format!("IPC send failed: {}", e)))?;

        match tokio::time::timeout(std::time::Duration::from_secs(30), rx).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => Err(AppError::Ipc("Response channel dropped".to_string())),
            Err(_) => {
                let mut pending = self.pending_requests.lock().await;
                pending.remove(&request_id);
                Err(AppError::Ipc("RDP session open timeout".to_string()))
            }
        }
    }

    /// Send an input event to an RDP session.
    pub fn send_input(&self, session_id: &str, input: RdpInputEvent) -> AppResult<()> {
        let msg = Message::RdpInput {
            session_id: session_id.to_string(),
            input,
        };
        self.channel
            .send(&msg)
            .map_err(|e| AppError::Ipc(format!("IPC send failed: {}", e)))
    }

    /// Send a resize event to an RDP session.
    pub fn resize(&self, session_id: &str, width: u16, height: u16) -> AppResult<()> {
        let msg = Message::RdpResize {
            session_id: session_id.to_string(),
            width,
            height,
        };
        self.channel
            .send(&msg)
            .map_err(|e| AppError::Ipc(format!("IPC send failed: {}", e)))
    }

    /// Close an RDP session.
    pub fn close_session(&self, session_id: &str) -> AppResult<()> {
        let msg = Message::RdpSessionClose {
            session_id: session_id.to_string(),
        };
        self.channel
            .send(&msg)
            .map_err(|e| AppError::Ipc(format!("IPC send failed: {}", e)))
    }

    /// Process incoming messages from the proxy.
    pub async fn process_incoming(&self) -> AppResult<()> {
        loop {
            let mut guard = self
                .read_async_fd
                .ready(Interest::READABLE)
                .await
                .map_err(|e| AppError::Ipc(format!("AsyncFd ready failed: {}", e)))?;

            loop {
                match self.channel.try_recv() {
                    Ok(msg) => {
                        self.handle_message(msg).await;
                    }
                    Err(shared::ipc::IpcError::Io(ref e))
                        if e.kind() == io::ErrorKind::WouldBlock =>
                    {
                        guard.clear_ready();
                        break;
                    }
                    Err(shared::ipc::IpcError::ConnectionClosed) => {
                        info!("RDP proxy IPC connection closed");
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

    async fn handle_message(&self, msg: Message) {
        match msg {
            Message::RdpSessionOpened {
                request_id,
                session_id,
                success,
                desktop_width,
                desktop_height,
                error,
            } => {
                debug!(
                    request_id = request_id,
                    session_id = %session_id,
                    success = success,
                    "RDP session opened response"
                );

                let response = RdpSessionOpened {
                    request_id,
                    session_id,
                    success,
                    desktop_width,
                    desktop_height,
                    error,
                };

                let mut pending = self.pending_requests.lock().await;
                if let Some(tx) = pending.remove(&request_id) {
                    let _ = tx.send(response);
                }
            }

            Message::RdpDisplayUpdate {
                session_id,
                x,
                y,
                width,
                height,
                png_data,
            } => {
                debug!(
                    session_id = %session_id,
                    x, y, width, height,
                    png_bytes = png_data.len(),
                    "IPC received RdpDisplayUpdate"
                );
                let senders = self.session_display_senders.lock().await;
                if let Some(tx) = senders.get(&session_id) {
                    let update = RdpDisplayUpdate {
                        x,
                        y,
                        width,
                        height,
                        png_data,
                    };
                    if tx.send(update).await.is_err() {
                        warn!(session_id = %session_id, "Failed to forward RDP display update, WebSocket dropped");
                    } else {
                        debug!(session_id = %session_id, "RDP display update forwarded to WebSocket channel");
                    }
                } else {
                    warn!(session_id = %session_id, "RDP display update but no WebSocket subscribed");
                }
            }

            _ => {
                debug!(?msg, "Ignoring unexpected message from RDP proxy");
            }
        }
    }
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    use libc::{fcntl, F_GETFL, F_SETFL, O_NONBLOCK};
    // SAFETY: fcntl with valid arguments on a valid fd.
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
    use secrecy::SecretString;
    use std::os::unix::io::AsRawFd;

    fn make_test_request(session_id: &str, host: &str, port: u16) -> RdpSessionOpenRequest {
        RdpSessionOpenRequest {
            session_id: session_id.to_string(),
            user_id: "user".to_string(),
            asset_id: "asset".to_string(),
            asset_host: host.to_string(),
            asset_port: port,
            username: "admin".to_string(),
            password: Some(SecretString::from("test-password".to_string())),
            domain: Some("WORKGROUP".to_string()),
            desktop_width: 1280,
            desktop_height: 720,
        }
    }

    // ==================== RdpSessionOpenRequest Tests ====================

    #[test]
    fn test_rdp_session_open_request() {
        let request = make_test_request("rdp-123", "10.0.0.50", 3389);
        assert_eq!(request.session_id, "rdp-123");
        assert_eq!(request.asset_port, 3389);
        assert_eq!(request.desktop_width, 1280);
        assert_eq!(request.desktop_height, 720);
    }

    #[test]
    fn test_rdp_session_open_request_clone() {
        let request = make_test_request("clone-rdp", "10.0.0.1", 3389);
        let cloned = request.clone();
        assert_eq!(request.session_id, cloned.session_id);
        assert_eq!(request.asset_host, cloned.asset_host);
        assert_eq!(request.asset_port, cloned.asset_port);
        assert_eq!(request.desktop_width, cloned.desktop_width);
    }

    #[test]
    fn test_rdp_session_open_request_debug_redacts_password() {
        let request = make_test_request("debug-rdp", "host.local", 3389);
        let debug_str = format!("{:?}", request);

        assert!(debug_str.contains("RdpSessionOpenRequest"));
        assert!(debug_str.contains("debug-rdp"));
        assert!(debug_str.contains("host.local"));
        assert!(
            !debug_str.contains("test-password"),
            "Password must not appear in Debug output"
        );
        assert!(debug_str.contains("[REDACTED]"));
    }

    #[test]
    fn test_rdp_session_open_request_no_password() {
        let mut request = make_test_request("no-pass", "host", 3389);
        request.password = None;
        let debug_str = format!("{:?}", request);
        assert!(debug_str.contains("None"));
    }

    #[test]
    fn test_rdp_session_open_request_no_domain() {
        let mut request = make_test_request("no-domain", "host", 3389);
        request.domain = None;
        assert!(request.domain.is_none());
    }

    #[test]
    fn test_rdp_session_open_request_custom_resolution() {
        let mut request = make_test_request("res", "host", 3389);
        request.desktop_width = 3840;
        request.desktop_height = 2160;
        assert_eq!(request.desktop_width, 3840);
        assert_eq!(request.desktop_height, 2160);
    }

    #[test]
    fn test_rdp_session_open_request_ipv6_host() {
        let request = make_test_request("ipv6", "2001:db8::1", 3389);
        assert_eq!(request.asset_host, "2001:db8::1");
    }

    #[test]
    fn test_rdp_session_open_request_alternate_port() {
        let request = make_test_request("alt-port", "server.local", 13389);
        assert_eq!(request.asset_port, 13389);
    }

    // ==================== RdpSessionOpened Tests ====================

    #[test]
    fn test_rdp_session_opened_success() {
        let response = RdpSessionOpened {
            request_id: 1,
            session_id: "rdp-123".to_string(),
            success: true,
            desktop_width: 1920,
            desktop_height: 1080,
            error: None,
        };
        assert!(response.success);
        assert!(response.error.is_none());
        assert_eq!(response.desktop_width, 1920);
    }

    #[test]
    fn test_rdp_session_opened_failure() {
        let response = RdpSessionOpened {
            request_id: 1,
            session_id: "rdp-123".to_string(),
            success: false,
            desktop_width: 0,
            desktop_height: 0,
            error: Some("Connection refused".to_string()),
        };
        assert!(!response.success);
        assert_eq!(response.error.unwrap(), "Connection refused");
    }

    #[test]
    fn test_rdp_session_opened_clone() {
        let response = RdpSessionOpened {
            request_id: 42,
            session_id: "clone-rdp".to_string(),
            success: true,
            desktop_width: 1280,
            desktop_height: 720,
            error: None,
        };
        let cloned = response.clone();
        assert_eq!(response.request_id, cloned.request_id);
        assert_eq!(response.session_id, cloned.session_id);
        assert_eq!(response.desktop_width, cloned.desktop_width);
    }

    #[test]
    fn test_rdp_session_opened_debug() {
        let response = RdpSessionOpened {
            request_id: 999,
            session_id: "debug-rdp".to_string(),
            success: false,
            desktop_width: 0,
            desktop_height: 0,
            error: Some("Auth failed".to_string()),
        };
        let debug_str = format!("{:?}", response);
        assert!(debug_str.contains("RdpSessionOpened"));
        assert!(debug_str.contains("999"));
        assert!(debug_str.contains("Auth failed"));
    }

    #[test]
    fn test_rdp_session_opened_various_errors() {
        let errors = [
            "Connection refused",
            "Authentication failed",
            "Timeout",
            "TLS negotiation failed",
            "Protocol error",
        ];
        for error_msg in errors {
            let response = RdpSessionOpened {
                request_id: 1,
                session_id: "test".to_string(),
                success: false,
                desktop_width: 0,
                desktop_height: 0,
                error: Some(error_msg.to_string()),
            };
            assert!(!response.success);
            assert_eq!(response.error.as_deref(), Some(error_msg));
        }
    }

    // ==================== RdpDisplayUpdate Tests ====================

    #[test]
    fn test_rdp_display_update_construction() {
        let update = RdpDisplayUpdate {
            x: 100,
            y: 200,
            width: 640,
            height: 480,
            png_data: vec![0x89, 0x50, 0x4E, 0x47],
        };
        assert_eq!(update.x, 100);
        assert_eq!(update.y, 200);
        assert_eq!(update.width, 640);
        assert_eq!(update.height, 480);
        assert_eq!(update.png_data.len(), 4);
    }

    #[test]
    fn test_rdp_display_update_debug() {
        let update = RdpDisplayUpdate {
            x: 0,
            y: 0,
            width: 1920,
            height: 1080,
            png_data: vec![1, 2, 3],
        };
        let debug_str = format!("{:?}", update);
        assert!(debug_str.contains("RdpDisplayUpdate"));
    }

    #[test]
    fn test_rdp_display_update_origin() {
        let update = RdpDisplayUpdate {
            x: 0,
            y: 0,
            width: 100,
            height: 100,
            png_data: vec![],
        };
        assert_eq!(update.x, 0);
        assert_eq!(update.y, 0);
    }

    #[test]
    fn test_rdp_display_update_empty_png() {
        let update = RdpDisplayUpdate {
            x: 0,
            y: 0,
            width: 0,
            height: 0,
            png_data: vec![],
        };
        assert!(update.png_data.is_empty());
    }

    // ==================== set_nonblocking Tests ====================

    #[test]
    fn test_set_nonblocking() {
        let (read_fd, _write_fd) = nix::unistd::pipe().unwrap();
        let result = set_nonblocking(read_fd.as_raw_fd());
        assert!(result.is_ok());

        use libc::{fcntl, F_GETFL, O_NONBLOCK};
        let flags = unsafe { fcntl(read_fd.as_raw_fd(), F_GETFL) };
        assert!(flags & O_NONBLOCK != 0);
    }

    #[test]
    fn test_set_nonblocking_preserves_flags() {
        let (read_fd, _write_fd) = nix::unistd::pipe().unwrap();
        use libc::{fcntl, F_GETFL, O_NONBLOCK};
        let original_flags = unsafe { fcntl(read_fd.as_raw_fd(), F_GETFL) };
        set_nonblocking(read_fd.as_raw_fd()).unwrap();
        let new_flags = unsafe { fcntl(read_fd.as_raw_fd(), F_GETFL) };
        assert_eq!(new_flags, original_flags | O_NONBLOCK);
    }

    #[test]
    fn test_set_nonblocking_idempotent() {
        let (read_fd, _write_fd) = nix::unistd::pipe().unwrap();
        set_nonblocking(read_fd.as_raw_fd()).unwrap();
        set_nonblocking(read_fd.as_raw_fd()).unwrap();
        use libc::{fcntl, F_GETFL, O_NONBLOCK};
        let flags = unsafe { fcntl(read_fd.as_raw_fd(), F_GETFL) };
        assert!(flags & O_NONBLOCK != 0);
    }

    // ==================== Request ID Counter Tests ====================

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
        assert_eq!(id2, 0);
    }

    // ==================== Display Update Channel Tests ====================

    #[tokio::test]
    async fn test_display_update_channel_send_receive() {
        let (tx, mut rx) = mpsc::channel::<RdpDisplayUpdate>(16);
        let update = RdpDisplayUpdate {
            x: 100,
            y: 200,
            width: 640,
            height: 480,
            png_data: vec![0x89, b'P', b'N', b'G'],
        };
        tx.send(update).await.unwrap();
        let received = rx.recv().await.unwrap();
        assert_eq!(received.x, 100);
        assert_eq!(received.y, 200);
        assert_eq!(received.width, 640);
        assert_eq!(received.height, 480);
        assert_eq!(received.png_data, vec![0x89, b'P', b'N', b'G']);
    }

    #[tokio::test]
    async fn test_display_update_channel_closed_sender() {
        let (tx, mut rx) = mpsc::channel::<RdpDisplayUpdate>(16);
        drop(tx);
        assert!(rx.recv().await.is_none(), "closed sender yields None");
    }

    #[tokio::test]
    async fn test_display_update_multiple_frames() {
        let (tx, mut rx) = mpsc::channel::<RdpDisplayUpdate>(16);
        for i in 0u16..5 {
            tx.send(RdpDisplayUpdate {
                x: i * 10,
                y: i * 20,
                width: 128,
                height: 64,
                png_data: vec![i as u8; 100],
            })
            .await
            .unwrap();
        }
        for i in 0u16..5 {
            let update = rx.recv().await.unwrap();
            assert_eq!(update.x, i * 10);
            assert_eq!(update.y, i * 20);
        }
    }

    #[test]
    fn test_display_update_large_png_data() {
        let update = RdpDisplayUpdate {
            x: 0,
            y: 0,
            width: 1280,
            height: 720,
            png_data: vec![0xAB; 200_000],
        };
        assert_eq!(update.png_data.len(), 200_000);
    }

    #[test]
    fn test_rdp_display_update_debug_new() {
        let update = RdpDisplayUpdate {
            x: 10,
            y: 20,
            width: 100,
            height: 50,
            png_data: vec![1, 2, 3],
        };
        let debug = format!("{:?}", update);
        assert!(debug.contains("RdpDisplayUpdate"));
        assert!(debug.contains("10"));
        assert!(debug.contains("20"));
    }

    // ==================== Session Opened Response Edge Cases ====================

    #[test]
    fn test_rdp_session_opened_width_height() {
        let response = RdpSessionOpened {
            request_id: 1,
            session_id: "s1".to_string(),
            success: true,
            error: None,
            desktop_width: 1920,
            desktop_height: 1080,
        };
        assert_eq!(response.desktop_width, 1920);
        assert_eq!(response.desktop_height, 1080);
    }

    #[test]
    fn test_rdp_session_opened_default_resolution() {
        let response = RdpSessionOpened {
            request_id: 1,
            session_id: "s2".to_string(),
            success: true,
            error: None,
            desktop_width: 1280,
            desktop_height: 720,
        };
        assert_eq!(response.desktop_width, 1280);
        assert_eq!(response.desktop_height, 720);
    }

    #[test]
    fn test_rdp_session_open_request_unicode_hostname() {
        let request = RdpSessionOpenRequest {
            session_id: "s".to_string(),
            user_id: "u".to_string(),
            asset_id: "a".to_string(),
            asset_host: "serveur.example.com".to_string(),
            asset_port: 3389,
            username: "user".to_string(),
            password: None,
            domain: None,
            desktop_width: 1280,
            desktop_height: 720,
        };
        assert_eq!(request.asset_host, "serveur.example.com");
    }

    #[test]
    fn test_rdp_session_open_request_non_standard_port() {
        let request = make_test_request("s", "host", 13389);
        assert_eq!(request.asset_port, 13389);
    }

    #[test]
    fn test_rdp_session_open_request_empty_domain() {
        let request = RdpSessionOpenRequest {
            session_id: "s".to_string(),
            user_id: "u".to_string(),
            asset_id: "a".to_string(),
            asset_host: "host".to_string(),
            asset_port: 3389,
            username: "user".to_string(),
            password: None,
            domain: Some(String::new()),
            desktop_width: 1280,
            desktop_height: 720,
        };
        assert_eq!(request.domain.as_deref(), Some(""));
    }
}
