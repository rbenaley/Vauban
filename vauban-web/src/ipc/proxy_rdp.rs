//! IPC client for communication with vauban-proxy-rdp.
//!
//! Provides async methods to open RDP sessions, send input events,
//! and receive display updates from RDP sessions.
//!
//! Transport/correlation is owned by [`CorrelatedIpcCore`] (30 s timeout on
//! open / cert fetch — INV-CORR-5).

use crate::error::{AppError, AppResult};
use crate::ipc::correlated::{CorrelatedIpcCore, deliver_or_warn};
use secrecy::{ExposeSecret, SecretString};
use shared::messages::{Message, RdpInputEvent, SensitiveString};
use std::collections::HashMap;
use std::io;
use std::os::unix::io::RawFd;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Duration;
use tokio::sync::{Mutex, mpsc, oneshot};
use tracing::{debug, trace, warn};

const RDP_IPC_TIMEOUT: Duration = Duration::from_secs(30);

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
    /// VAU-001: pinned `SHA256:<base64>` fingerprint of the target server's
    /// TLS SPKI (from `assets.connection_config.rdp_server_cert_fingerprint`).
    /// The proxy refuses the TLS handshake fail-closed on mismatch and
    /// refuses to connect at all when this is `None`. Mirrors the SSH
    /// `expected_host_key` contract.
    pub expected_cert_fingerprint: Option<String>,
    /// Cryptographic session token (BLAKE3-keyed MAC) issued by
    /// vauban-access, verified by vauban-proxy-rdp BEFORE
    /// `AccessGuard::authorize`. Mirrors `SshSessionOpenRequest`.
    pub session_token: Vec<u8>,
    /// NLA auth mode from `connection_config.rdp_auth_mode`. Fail-closed:
    /// the proxy never falls back to NTLM when Kerberos is selected.
    pub rdp_auth_mode: shared::messages::RdpAuthMode,
}

/// Identity material required to mint the crypto token that gates the
/// supervisor TCP broker for an RDP server-certificate fetch. Mirrors
/// [`super::proxy_ssh::HostKeyFetchIdentity`].
///
/// The TCP broker is crypto-gated: every connect requires a fresh token
/// minted by vauban-access. The cert-fetch path is no exception -- without
/// this gate a compromised vauban-web could use `RdpFetchServerCert` to
/// enumerate the internal network.
pub struct CertFetchIdentity<'a> {
    pub access_client: &'a super::AccessIpcClient,
    pub user_uuid: &'a str,
    pub asset_uuid: &'a str,
    /// Whether the original web caller holds Casbin `assets:manage`. When
    /// `true`, the fetch uses
    /// [`super::AccessIpcClient::issue_diagnostic_token`] (skips the
    /// access-rule re-check, since admins typically have no explicit rule
    /// per asset). When `false`, the legacy session-token verb keeps the
    /// caller gated by their access rule.
    pub caller_has_assets_manage: bool,
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
            .field("expected_cert_fingerprint", &self.expected_cert_fingerprint)
            .field("rdp_auth_mode", &self.rdp_auth_mode)
            .finish()
    }
}

/// Sender type for pending RDP server-certificate fetch responses.
///
/// Carries `(success, server_spki_b64, cert_fingerprint, error)`.
type ServerCertResponseSender =
    oneshot::Sender<(bool, Option<String>, Option<String>, Option<String>)>;

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

/// Event from an RDP session forwarded to the WebSocket handler.
#[derive(Debug)]
pub enum RdpSessionEvent {
    /// Display region update (PNG-encoded bitmap).
    DisplayUpdate {
        x: u16,
        y: u16,
        width: u16,
        height: u16,
        png_data: Vec<u8>,
    },
    /// Desktop size changed (after reactivation/resize).
    DesktopResize { width: u16, height: u16 },
    /// H.264 encoded video frame.
    VideoFrame {
        timestamp_us: u64,
        is_keyframe: bool,
        width: u16,
        height: u16,
        data: Vec<u8>,
    },
}

/// Async client for communicating with vauban-proxy-rdp.
pub struct ProxyRdpClient {
    core: CorrelatedIpcCore,
    pending_requests: StdMutex<HashMap<u64, oneshot::Sender<RdpSessionOpened>>>,
    /// Per-session event senders: session_id -> Sender.
    session_display_senders: Mutex<HashMap<String, mpsc::Sender<RdpSessionEvent>>>,
    /// Pre-created receivers waiting to be claimed by WebSocket.
    session_display_receivers: Mutex<HashMap<String, mpsc::Receiver<RdpSessionEvent>>>,
    /// Pending RDP server-certificate fetch requests waiting for responses.
    pending_cert_requests: StdMutex<HashMap<u64, ServerCertResponseSender>>,
}

impl ProxyRdpClient {
    pub fn new(read_fd: RawFd, write_fd: RawFd) -> io::Result<Arc<Self>> {
        Ok(Arc::new(Self {
            core: CorrelatedIpcCore::from_fds(read_fd, write_fd)?,
            pending_requests: StdMutex::new(HashMap::new()),
            session_display_senders: Mutex::new(HashMap::new()),
            session_display_receivers: Mutex::new(HashMap::new()),
            pending_cert_requests: StdMutex::new(HashMap::new()),
        }))
    }

    /// Subscribe to session events (display updates, resize notifications).
    pub async fn subscribe_session(&self, session_id: &str) -> mpsc::Receiver<RdpSessionEvent> {
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
        self.session_display_senders.lock().await.remove(session_id);
        debug!(session_id = %session_id, "WebSocket unsubscribed from RDP session");
    }

    /// Request to open a new RDP session.
    pub async fn open_session(
        &self,
        request: RdpSessionOpenRequest,
    ) -> AppResult<RdpSessionOpened> {
        let request_id = self.core.alloc_id();
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
            expected_cert_fingerprint: request.expected_cert_fingerprint,
            session_token: request.session_token,
            rdp_auth_mode: request.rdp_auth_mode,
        };

        self.core
            .request(
                &self.pending_requests,
                request_id,
                &msg,
                Some(RDP_IPC_TIMEOUT),
            )
            .await
            .map_err(|e| e.into_app_ipc())
    }

    /// Send an input event to an RDP session.
    pub fn send_input(&self, session_id: &str, input: RdpInputEvent) -> AppResult<()> {
        let msg = Message::RdpInput {
            session_id: session_id.to_string(),
            input,
        };
        self.core
            .send_fire_and_forget(&msg)
            .map_err(|e| e.into_app_ipc())
    }

    /// Send a resize event to an RDP session.
    pub fn resize(&self, session_id: &str, width: u16, height: u16) -> AppResult<()> {
        let msg = Message::RdpResize {
            session_id: session_id.to_string(),
            width,
            height,
        };
        self.core
            .send_fire_and_forget(&msg)
            .map_err(|e| e.into_app_ipc())
    }

    /// Enable or disable H.264 video mode for a session.
    pub fn set_video_mode(&self, session_id: &str, enabled: bool) -> AppResult<()> {
        let msg = Message::RdpSetVideoMode {
            session_id: session_id.to_string(),
            enabled,
        };
        self.core
            .send_fire_and_forget(&msg)
            .map_err(|e| e.into_app_ipc())
    }

    /// Close an RDP session.
    pub fn close_session(&self, session_id: &str) -> AppResult<()> {
        let msg = Message::RdpSessionClose {
            session_id: session_id.to_string(),
        };
        self.core
            .send_fire_and_forget(&msg)
            .map_err(|e| e.into_app_ipc())
    }

    /// VAU-001: fetch the target RDP server's TLS certificate SPKI (TOFU
    /// pinning workflow). Sends an `RdpFetchServerCert` request to the
    /// proxy, which performs a minimal RDP/X.224 + TLS handshake (accept-any
    /// verifier, no pin yet), extracts the SPKI, and closes the connection
    /// WITHOUT CredSSP/NLA.
    ///
    /// When a `supervisor` is provided (sandboxed / Capsicum mode), the
    /// method first asks the supervisor to broker the TCP connection to
    /// `host:port` and pass the FD to the RDP proxy via `SCM_RIGHTS`. The
    /// synthetic session id `"fetch-rdpcert-{request_id}"` matches the
    /// pre-connected FD to the incoming `RdpFetchServerCert` message.
    ///
    /// Strictly mirrors [`super::proxy_ssh::ProxySshClient::fetch_host_key`].
    ///
    /// Returns `(server_spki_base64, sha256_fingerprint)` on success.
    pub async fn fetch_server_cert(
        &self,
        host: &str,
        port: u16,
        supervisor: Option<&super::SupervisorClient>,
        identity: Option<CertFetchIdentity<'_>>,
    ) -> AppResult<(String, String)> {
        let request_id = self.core.alloc_id();

        debug!(
            request_id = request_id,
            host = %host,
            port = port,
            "Fetching RDP server certificate"
        );

        // Under supervisor (Capsicum sandbox): broker the TCP connect BEFORE
        // sending the fetch request. The broker is crypto-gated, so a token
        // must be minted by vauban-access. Admin (`assets:manage`) callers
        // use the diagnostic-token verb (skips access-rule re-check); other
        // callers stay on the legacy session-token verb. Mirrors SSH.
        if let Some(sv) = supervisor {
            let identity = identity.ok_or_else(|| {
                AppError::Ipc(
                    "fetch_server_cert: identity is required when supervisor is set \
                     (the TCP broker is crypto-gated; a session token must be minted)"
                        .to_string(),
                )
            })?;
            let fetch_session_id = format!("fetch-rdpcert-{}", request_id);
            let token_params = shared::session_token::SessionTokenParams {
                session_id: fetch_session_id.clone(),
                user_uuid: identity.user_uuid.to_string(),
                asset_uuid: identity.asset_uuid.to_string(),
                protocol: "rdp".to_string(),
                host: host.to_string(),
                port,
                target_service: shared::messages::Service::ProxyRdp,
            };
            let session_token = if identity.caller_has_assets_manage {
                identity
                    .access_client
                    .issue_diagnostic_token(token_params, true)
                    .await?
            } else {
                identity
                    .access_client
                    .issue_session_token(token_params)
                    .await?
            };
            debug!(
                request_id = request_id,
                fetch_session_id = %fetch_session_id,
                "Requesting TCP connection from supervisor for RDP cert fetch"
            );
            match sv
                .request_tcp_connect(
                    &fetch_session_id,
                    host,
                    port,
                    shared::messages::Service::ProxyRdp,
                    session_token,
                )
                .await
            {
                Ok(result) if result.success => {
                    debug!(
                        request_id = request_id,
                        "Supervisor established TCP connection for RDP cert fetch"
                    );
                }
                Ok(result) => {
                    let err = result
                        .error
                        .unwrap_or_else(|| "TCP connect failed".to_string());
                    warn!(
                        request_id = request_id,
                        error = %err,
                        "Supervisor TCP connect failed for RDP cert fetch"
                    );
                    return Err(AppError::Ipc(format!(
                        "Supervisor TCP connect failed: {}",
                        err
                    )));
                }
                Err(e) => {
                    warn!(
                        request_id = request_id,
                        error = %e,
                        "Supervisor TCP connect request failed for RDP cert fetch"
                    );
                    return Err(AppError::Ipc(format!(
                        "Supervisor TCP connect request failed: {}",
                        e
                    )));
                }
            }
        }

        let msg = Message::RdpFetchServerCert {
            request_id,
            asset_host: host.to_string(),
            asset_port: port,
        };

        match self
            .core
            .request(
                &self.pending_cert_requests,
                request_id,
                &msg,
                Some(RDP_IPC_TIMEOUT),
            )
            .await
        {
            Ok((true, Some(spki), Some(fp), _)) => Ok((spki, fp)),
            Ok((false, _, _, Some(err))) => {
                Err(AppError::Ipc(format!("RDP cert fetch failed: {}", err)))
            }
            Ok(_) => Err(AppError::Ipc(
                "RDP cert fetch returned unexpected response".to_string(),
            )),
            Err(e) => Err(e.into_app_ipc()),
        }
    }

    /// Process incoming messages from the proxy.
    pub async fn process_incoming(&self) -> AppResult<()> {
        self.core
            .process_loop(|msg| async {
                self.handle_message(msg).await;
            })
            .await
            .map_err(|e| e.into_app_ipc())
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

                deliver_or_warn(&self.pending_requests, request_id, response, "proxy_rdp");
            }

            Message::RdpServerCertResult {
                request_id,
                success,
                server_spki,
                cert_fingerprint,
                error,
            } => {
                debug!(
                    request_id = request_id,
                    success = success,
                    "RDP server certificate result received"
                );

                deliver_or_warn(
                    &self.pending_cert_requests,
                    request_id,
                    (success, server_spki, cert_fingerprint, error),
                    "proxy_rdp",
                );
            }

            Message::RdpDisplayUpdate {
                session_id,
                x,
                y,
                width,
                height,
                png_data,
            } => {
                trace!(
                    session_id = %session_id,
                    x, y, width, height,
                    png_bytes = png_data.len(),
                    "IPC received RdpDisplayUpdate"
                );
                let senders = self.session_display_senders.lock().await;
                if let Some(tx) = senders.get(&session_id) {
                    let event = RdpSessionEvent::DisplayUpdate {
                        x,
                        y,
                        width,
                        height,
                        png_data,
                    };
                    if tx.send(event).await.is_err() {
                        warn!(session_id = %session_id, "Failed to forward RDP display update, WebSocket dropped");
                    } else {
                        trace!(session_id = %session_id, "RDP display update forwarded to WebSocket channel");
                    }
                } else {
                    warn!(session_id = %session_id, "RDP display update but no WebSocket subscribed");
                }
            }

            Message::RdpDesktopResize {
                session_id,
                width,
                height,
            } => {
                trace!(
                    session_id = %session_id,
                    width, height,
                    "IPC received RdpDesktopResize"
                );
                let senders = self.session_display_senders.lock().await;
                if let Some(tx) = senders.get(&session_id) {
                    let event = RdpSessionEvent::DesktopResize { width, height };
                    if tx.send(event).await.is_err() {
                        warn!(session_id = %session_id, "Failed to forward desktop resize, WebSocket dropped");
                    }
                }
            }

            Message::RdpVideoFrame {
                session_id,
                timestamp_us,
                is_keyframe,
                width,
                height,
                data,
            } => {
                trace!(
                    session_id = %session_id,
                    timestamp_us, is_keyframe,
                    width, height,
                    bytes = data.len(),
                    "IPC received RdpVideoFrame"
                );
                let senders = self.session_display_senders.lock().await;
                if let Some(tx) = senders.get(&session_id) {
                    let event = RdpSessionEvent::VideoFrame {
                        timestamp_us,
                        is_keyframe,
                        width,
                        height,
                        data,
                    };
                    if tx.send(event).await.is_err() {
                        warn!(session_id = %session_id, "Failed to forward video frame, WebSocket dropped");
                    }
                }
            }

            _ => {
                debug!(?msg, "Ignoring unexpected message from RDP proxy");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::correlated::set_nonblocking;
    use secrecy::SecretString;
    use std::os::unix::io::AsRawFd;
    use std::sync::atomic::{AtomicU64, Ordering};

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
            expected_cert_fingerprint: Some("SHA256:dGVzdA==".to_string()),
            session_token: Vec::new(),
            rdp_auth_mode: shared::messages::RdpAuthMode::Ntlm,
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

    // ==================== RdpSessionEvent Tests ====================

    #[test]
    fn test_rdp_session_event_display_update() {
        let event = RdpSessionEvent::DisplayUpdate {
            x: 100,
            y: 200,
            width: 640,
            height: 480,
            png_data: vec![0x89, 0x50, 0x4E, 0x47],
        };
        if let RdpSessionEvent::DisplayUpdate {
            x,
            y,
            width,
            height,
            png_data,
        } = &event
        {
            assert_eq!(*x, 100);
            assert_eq!(*y, 200);
            assert_eq!(*width, 640);
            assert_eq!(*height, 480);
            assert_eq!(png_data.len(), 4);
        } else {
            panic!("Expected DisplayUpdate");
        }
        let debug_str = format!("{:?}", event);
        assert!(debug_str.contains("DisplayUpdate"));
    }

    #[test]
    fn test_rdp_session_event_desktop_resize() {
        let event = RdpSessionEvent::DesktopResize {
            width: 1920,
            height: 1080,
        };
        if let RdpSessionEvent::DesktopResize { width, height } = &event {
            assert_eq!(*width, 1920);
            assert_eq!(*height, 1080);
        } else {
            panic!("Expected DesktopResize");
        }
        let debug_str = format!("{:?}", event);
        assert!(debug_str.contains("DesktopResize"));
    }

    // ==================== set_nonblocking Tests ====================

    #[test]
    fn test_set_nonblocking() {
        let (read_fd, _write_fd) = nix::unistd::pipe().unwrap();
        let result = set_nonblocking(read_fd.as_raw_fd());
        assert!(result.is_ok());

        use libc::{F_GETFL, O_NONBLOCK, fcntl};
        let flags = unsafe { fcntl(read_fd.as_raw_fd(), F_GETFL) };
        assert!(flags & O_NONBLOCK != 0);
    }

    #[test]
    fn test_set_nonblocking_preserves_flags() {
        let (read_fd, _write_fd) = nix::unistd::pipe().unwrap();
        use libc::{F_GETFL, O_NONBLOCK, fcntl};
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
        use libc::{F_GETFL, O_NONBLOCK, fcntl};
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

    // ==================== Session Event Channel Tests ====================

    #[tokio::test]
    async fn test_session_event_channel_send_receive() {
        let (tx, mut rx) = mpsc::channel::<RdpSessionEvent>(16);
        let event = RdpSessionEvent::DisplayUpdate {
            x: 100,
            y: 200,
            width: 640,
            height: 480,
            png_data: vec![0x89, b'P', b'N', b'G'],
        };
        tx.send(event).await.unwrap();
        let received = rx.recv().await.unwrap();
        if let RdpSessionEvent::DisplayUpdate {
            x,
            y,
            width,
            height,
            png_data,
        } = received
        {
            assert_eq!(x, 100);
            assert_eq!(y, 200);
            assert_eq!(width, 640);
            assert_eq!(height, 480);
            assert_eq!(png_data, vec![0x89, b'P', b'N', b'G']);
        } else {
            panic!("Expected DisplayUpdate");
        }
    }

    #[tokio::test]
    async fn test_session_event_channel_desktop_resize() {
        let (tx, mut rx) = mpsc::channel::<RdpSessionEvent>(16);
        let event = RdpSessionEvent::DesktopResize {
            width: 1920,
            height: 1080,
        };
        tx.send(event).await.unwrap();
        let received = rx.recv().await.unwrap();
        if let RdpSessionEvent::DesktopResize { width, height } = received {
            assert_eq!(width, 1920);
            assert_eq!(height, 1080);
        } else {
            panic!("Expected DesktopResize");
        }
    }

    #[tokio::test]
    async fn test_session_event_channel_video_frame() {
        let (tx, mut rx) = mpsc::channel::<RdpSessionEvent>(16);
        let h264_data = vec![0x00, 0x00, 0x00, 0x01, 0x67, 0x42];
        let event = RdpSessionEvent::VideoFrame {
            timestamp_us: 16666,
            is_keyframe: true,
            width: 1920,
            height: 1080,
            data: h264_data.clone(),
        };
        tx.send(event).await.unwrap();
        let received = rx.recv().await.unwrap();
        if let RdpSessionEvent::VideoFrame {
            timestamp_us,
            is_keyframe,
            width,
            height,
            data,
        } = received
        {
            assert_eq!(timestamp_us, 16666);
            assert!(is_keyframe);
            assert_eq!(width, 1920);
            assert_eq!(height, 1080);
            assert_eq!(data, h264_data);
        } else {
            panic!("Expected VideoFrame");
        }
    }

    #[tokio::test]
    async fn test_session_event_channel_video_frame_delta() {
        let (tx, mut rx) = mpsc::channel::<RdpSessionEvent>(16);
        let event = RdpSessionEvent::VideoFrame {
            timestamp_us: 33333,
            is_keyframe: false,
            width: 1280,
            height: 720,
            data: vec![0x00, 0x00, 0x01, 0x41],
        };
        tx.send(event).await.unwrap();
        let received = rx.recv().await.unwrap();
        if let RdpSessionEvent::VideoFrame { is_keyframe, .. } = received {
            assert!(!is_keyframe);
        } else {
            panic!("Expected VideoFrame");
        }
    }

    #[tokio::test]
    async fn test_session_event_channel_mixed_events() {
        let (tx, mut rx) = mpsc::channel::<RdpSessionEvent>(16);
        tx.send(RdpSessionEvent::DisplayUpdate {
            x: 0,
            y: 0,
            width: 100,
            height: 100,
            png_data: vec![0x89],
        })
        .await
        .unwrap();
        tx.send(RdpSessionEvent::VideoFrame {
            timestamp_us: 1000,
            is_keyframe: true,
            width: 1920,
            height: 1080,
            data: vec![0, 0, 0, 1],
        })
        .await
        .unwrap();
        tx.send(RdpSessionEvent::DesktopResize {
            width: 2560,
            height: 1440,
        })
        .await
        .unwrap();

        assert!(matches!(
            rx.recv().await.unwrap(),
            RdpSessionEvent::DisplayUpdate { .. }
        ));
        assert!(matches!(
            rx.recv().await.unwrap(),
            RdpSessionEvent::VideoFrame { .. }
        ));
        assert!(matches!(
            rx.recv().await.unwrap(),
            RdpSessionEvent::DesktopResize { .. }
        ));
    }

    #[tokio::test]
    async fn test_session_event_channel_closed_sender() {
        let (tx, mut rx) = mpsc::channel::<RdpSessionEvent>(16);
        drop(tx);
        assert!(rx.recv().await.is_none(), "closed sender yields None");
    }

    #[tokio::test]
    async fn test_session_event_multiple_frames() {
        let (tx, mut rx) = mpsc::channel::<RdpSessionEvent>(16);
        for i in 0u16..5 {
            tx.send(RdpSessionEvent::DisplayUpdate {
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
            let received = rx.recv().await.unwrap();
            if let RdpSessionEvent::DisplayUpdate { x, y, .. } = received {
                assert_eq!(x, i * 10);
                assert_eq!(y, i * 20);
            } else {
                panic!("Expected DisplayUpdate");
            }
        }
    }

    #[test]
    fn test_session_event_large_png_data() {
        let event = RdpSessionEvent::DisplayUpdate {
            x: 0,
            y: 0,
            width: 1280,
            height: 720,
            png_data: vec![0xAB; 200_000],
        };
        if let RdpSessionEvent::DisplayUpdate { png_data, .. } = &event {
            assert_eq!(png_data.len(), 200_000);
        }
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
            expected_cert_fingerprint: None,
            session_token: Vec::new(),
            rdp_auth_mode: shared::messages::RdpAuthMode::Ntlm,
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
            expected_cert_fingerprint: None,
            session_token: Vec::new(),
            rdp_auth_mode: shared::messages::RdpAuthMode::Ntlm,
        };
        assert_eq!(request.domain.as_deref(), Some(""));
    }
}
