//! IPC message types for inter-process communication between Vauban services.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use zeroize::Zeroize;

/// A string wrapper for sensitive data transported via IPC.
///
/// `SensitiveString` provides three security properties:
/// - **Zeroize on drop**: the backing memory is overwritten with zeros when the
///   value goes out of scope, preventing credential remnants in freed memory.
/// - **Redacted Debug**: `format!("{:?}", val)` prints `[REDACTED]` instead of
///   the secret value, so credentials never leak through logging.
/// - **Transparent serde**: `#[serde(transparent)]` ensures bincode
///   serialization is byte-identical to a plain `String`, avoiding any IPC
///   protocol change.
///
/// This type is used exclusively inside `Message::SshSessionOpen` for the
/// credential fields (`password`, `private_key`, `passphrase`).
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SensitiveString(String);

impl SensitiveString {
    /// Create a new `SensitiveString` from a plain `String`.
    pub fn new(s: String) -> Self {
        Self(s)
    }

    /// Consume `self` and return the inner `String`.
    ///
    /// The caller takes ownership and responsibility for the secret material.
    /// Note: because `self` is consumed (not dropped), the destructor does
    /// **not** run -- the returned `String` must be consumed or zeroized by
    /// the caller.
    pub fn into_inner(self) -> String {
        // Use ManuallyDrop to prevent the Drop impl from zeroizing the
        // string we are about to hand out.
        let md = std::mem::ManuallyDrop::new(self);
        // SAFETY: we own the value and `ManuallyDrop` is repr(transparent).
        unsafe { std::ptr::read(&md.0) }
    }

    /// Borrow the inner string as `&str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SensitiveString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl Drop for SensitiveString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl PartialEq for SensitiveString {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl From<String> for SensitiveString {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for SensitiveString {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

/// Service identifier for routing messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Service {
    Supervisor,
    Web,
    Auth,
    Rbac,
    Vault,
    Audit,
    ProxySsh,
    ProxyRdp,
}

/// Control messages between supervisor and services.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControlMessage {
    /// Request to drain: stop accepting new requests.
    Drain,

    /// Response: service is now idle.
    DrainComplete { pending_requests: u32 },

    /// Heartbeat request from supervisor.
    Ping { seq: u64 },

    /// Heartbeat response from service.
    Pong { seq: u64, stats: ServiceStats },

    /// Immediate shutdown requested.
    Shutdown,
}

/// Service health statistics reported in Pong messages.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServiceStats {
    pub uptime_secs: u64,
    pub requests_processed: u64,
    pub requests_failed: u64,
    pub active_connections: u32,
    pub pending_requests: u32,
}

/// Authentication result from vauban-auth.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthResult {
    Success {
        user_id: String,
        session_id: String,
        roles: Vec<String>,
    },
    Failure {
        reason: String,
    },
    MfaRequired {
        challenge_id: String,
    },
}

/// RBAC authorization result from vauban-rbac.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RbacResult {
    pub allowed: bool,
    pub reason: Option<String>,
}

/// Audit event types for vauban-audit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditEventType {
    AuthSuccess,
    AuthFailure,
    SessionStart,
    SessionEnd,
    CommandExecuted,
    AccessDenied,
    PolicyChange,
}

/// Input events for RDP sessions, sent from browser to proxy.
///
/// Scancodes follow the PS/2 Set 1 encoding (same as IronRDP FastPath).
/// Extended keys (arrows, numpad enter, etc.) use 0xE0xx codes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RdpInputEvent {
    /// Key pressed (scancode = PS/2 Set 1 make code).
    KeyPressed { scancode: u16 },
    /// Key released.
    KeyReleased { scancode: u16 },
    /// Mouse moved to absolute position.
    MouseMove { x: u16, y: u16 },
    /// Mouse button pressed (0=left, 1=middle, 2=right).
    MouseButtonPressed { button: u8 },
    /// Mouse button released.
    MouseButtonReleased { button: u8 },
    /// Mouse wheel scroll (vertical=true for Y axis, amount is direction).
    WheelScroll { vertical: bool, amount: i16 },

    // ── High-level variants from web frontend ─────────────────────
    // The proxy converts these into the low-level variants above.

    /// Mouse button with position (from web frontend).
    MouseButton { button: u8, pressed: bool, x: u16, y: u16 },
    /// Mouse wheel with raw delta (from web frontend).
    MouseWheel { delta_x: i16, delta_y: i16 },
    /// Keyboard event with JavaScript key code (from web frontend).
    /// The proxy maps `code` to a PS/2 scancode.
    Keyboard {
        code: String,
        key: String,
        pressed: bool,
        shift: bool,
        ctrl: bool,
        alt: bool,
        meta: bool,
    },
}

/// All IPC messages exchanged between services.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    // ========== Control messages ==========
    Control(ControlMessage),

    // ========== Authentication (Web -> Auth) ==========
    AuthRequest {
        request_id: u64,
        username: String,
        /// Credential type varies: password hash, token, etc.
        credential: Vec<u8>,
        source_ip: IpAddr,
    },
    AuthResponse {
        request_id: u64,
        result: AuthResult,
    },

    /// MFA verification (Web -> Auth)
    MfaVerify {
        request_id: u64,
        challenge_id: String,
        code: String,
    },
    MfaVerifyResponse {
        request_id: u64,
        success: bool,
        session_id: Option<String>,
    },

    // ========== RBAC (Web/Auth/Proxy -> Rbac) ==========
    RbacCheck {
        request_id: u64,
        subject: String,
        object: String,
        action: String,
    },
    RbacResponse {
        request_id: u64,
        result: RbacResult,
    },

    // ========== Vault (Auth/Proxy -> Vault) ==========
    VaultGetSecret {
        request_id: u64,
        path: String,
    },
    VaultSecretResponse {
        request_id: u64,
        /// Encrypted secret data, None if not found.
        data: Option<Vec<u8>>,
    },

    VaultGetCredential {
        request_id: u64,
        asset_id: String,
        credential_type: String,
    },
    VaultCredentialResponse {
        request_id: u64,
        /// Encrypted credential, None if not found.
        credential: Option<Vec<u8>>,
    },

    // ========== Vault Crypto (Any service -> Vault) ==========

    /// Encrypt plaintext with a named key domain (M-1, C-2).
    VaultEncrypt {
        request_id: u64,
        /// Key domain: "credentials", "mfa", etc.
        domain: String,
        /// Plaintext to encrypt.
        /// Wrapped in `SensitiveString` for zeroize-on-drop during IPC transport.
        plaintext: SensitiveString,
    },
    VaultEncryptResponse {
        request_id: u64,
        /// Versioned ciphertext (e.g. "v1:BASE64..."), None on error.
        ciphertext: Option<String>,
        error: Option<String>,
    },

    /// Decrypt ciphertext with a named key domain (M-1, C-2).
    VaultDecrypt {
        request_id: u64,
        /// Key domain: "credentials", "mfa", etc.
        domain: String,
        /// Versioned ciphertext as stored in the database.
        ciphertext: String,
    },
    VaultDecryptResponse {
        request_id: u64,
        /// Decrypted plaintext, None on error.
        /// Wrapped in `SensitiveString` for zeroize-on-drop during IPC transport.
        plaintext: Option<SensitiveString>,
        error: Option<String>,
    },

    // ========== Vault MFA (Web -> Vault) ==========

    /// Generate a new TOTP secret, encrypt it, and return both forms.
    /// The vault generates the secret, encrypts it for DB storage, and returns
    /// the plaintext as a `SensitiveString` (zeroize-on-drop) so the web layer
    /// can generate the QR code locally. QR generation is NOT done in the vault.
    VaultMfaGenerate {
        request_id: u64,
        /// Username (unused by vault, passed through for consistency).
        username: String,
        /// Issuer (unused by vault, passed through for consistency).
        issuer: String,
    },
    VaultMfaGenerateResponse {
        request_id: u64,
        /// Encrypted TOTP secret (store in DB as mfa_secret).
        encrypted_secret: Option<String>,
        /// Plaintext TOTP secret in base32 for QR code generation by the web layer.
        /// Wrapped in `SensitiveString` for zeroize-on-drop during IPC transport.
        plaintext_secret: Option<SensitiveString>,
        error: Option<String>,
    },

    /// Verify a TOTP code against an encrypted secret.
    VaultMfaVerify {
        request_id: u64,
        /// Encrypted TOTP secret as stored in DB.
        encrypted_secret: String,
        /// 6-digit TOTP code entered by the user.
        code: String,
    },
    VaultMfaVerifyResponse {
        request_id: u64,
        /// true if the code is valid for the current or adjacent time step.
        valid: bool,
        error: Option<String>,
    },

    /// Decrypt an encrypted TOTP secret and return the plaintext.
    /// Used by vauban-web to re-generate QR codes from existing encrypted secrets.
    VaultMfaGetSecret {
        request_id: u64,
        /// Encrypted TOTP secret as stored in DB.
        encrypted_secret: String,
    },
    VaultMfaGetSecretResponse {
        request_id: u64,
        /// Decrypted TOTP secret in base32, wrapped in `SensitiveString` for zeroize-on-drop.
        plaintext_secret: Option<SensitiveString>,
        error: Option<String>,
    },

    // ========== Audit (Web/Proxy -> Audit) ==========
    AuditEvent {
        timestamp: u64,
        event_type: AuditEventType,
        user_id: Option<String>,
        session_id: Option<String>,
        source_ip: Option<IpAddr>,
        details: String,
    },
    /// Acknowledgement from audit service.
    AuditAck {
        timestamp: u64,
    },

    /// Session recording chunk (Proxy -> Audit).
    SessionRecordingChunk {
        session_id: String,
        sequence: u64,
        data: Vec<u8>,
    },

    // ========== SSH Session (Web <-> ProxySsh) ==========
    /// Request to open an SSH session.
    SshSessionOpen {
        request_id: u64,
        /// UUID generated by vauban-web.
        session_id: String,
        /// Authenticated Vauban user ID.
        user_id: String,
        /// Asset UUID from database.
        asset_id: String,
        /// Target hostname or IP address.
        asset_host: String,
        /// SSH port (default 22).
        asset_port: u16,
        /// SSH username on target server.
        username: String,
        /// Terminal width in columns.
        terminal_cols: u16,
        /// Terminal height in rows.
        terminal_rows: u16,
        /// Authentication type: "password" or "private_key".
        auth_type: String,
        /// Password for password authentication (if auth_type == "password").
        /// Wrapped in `SensitiveString` for zeroize-on-drop and redacted Debug (H-10).
        password: Option<SensitiveString>,
        /// PEM-encoded private key (if auth_type == "private_key").
        /// Wrapped in `SensitiveString` for zeroize-on-drop and redacted Debug (H-10).
        private_key: Option<SensitiveString>,
        /// Passphrase for encrypted private key.
        /// Wrapped in `SensitiveString` for zeroize-on-drop and redacted Debug (H-10).
        passphrase: Option<SensitiveString>,
        /// Expected SSH host key in OpenSSH format (e.g. "ssh-ed25519 AAAA...").
        /// If set, the proxy MUST verify the server key matches before continuing.
        /// If None, host key verification is skipped (insecure, logged as warning).
        expected_host_key: Option<String>,
    },

    /// Response confirming session opened or error.
    SshSessionOpened {
        request_id: u64,
        session_id: String,
        success: bool,
        /// Error message if success is false.
        error: Option<String>,
    },

    /// Bidirectional terminal data (Web <-> ProxySsh).
    SshData {
        session_id: String,
        data: Vec<u8>,
    },

    /// Request to close an SSH session.
    SshSessionClose {
        session_id: String,
    },

    /// Terminal resize event.
    SshResize {
        session_id: String,
        cols: u16,
        rows: u16,
    },

    // ========== SSH Host Key (Web <-> ProxySsh) ==========
    /// Request to fetch the SSH host key from a target server.
    /// The proxy performs a minimal SSH handshake (key exchange only, no auth)
    /// and returns the server's public key.
    SshFetchHostKey {
        request_id: u64,
        /// Target hostname or IP address.
        asset_host: String,
        /// SSH port.
        asset_port: u16,
    },

    /// Response with the fetched SSH host key.
    SshHostKeyResult {
        request_id: u64,
        success: bool,
        /// Host key in OpenSSH format (e.g. "ssh-ed25519 AAAA...").
        host_key: Option<String>,
        /// SHA-256 fingerprint for display (e.g. "SHA256:abc123...").
        key_fingerprint: Option<String>,
        /// Error message if success is false.
        error: Option<String>,
    },

    // ========== RDP Session (Web <-> ProxyRdp) ==========

    /// Request to open an RDP session.
    RdpSessionOpen {
        request_id: u64,
        /// UUID generated by vauban-web.
        session_id: String,
        /// Authenticated Vauban user ID.
        user_id: String,
        /// Asset UUID from database.
        asset_id: String,
        /// Target hostname or IP address.
        asset_host: String,
        /// RDP port (default 3389).
        asset_port: u16,
        /// RDP username on target server.
        username: String,
        /// Password for RDP authentication.
        /// Wrapped in `SensitiveString` for zeroize-on-drop and redacted Debug (H-10).
        password: Option<SensitiveString>,
        /// Windows domain (optional).
        domain: Option<String>,
        /// Requested desktop width in pixels.
        desktop_width: u16,
        /// Requested desktop height in pixels.
        desktop_height: u16,
    },

    /// Response confirming RDP session opened or error.
    RdpSessionOpened {
        request_id: u64,
        session_id: String,
        success: bool,
        /// Actual desktop width negotiated with server.
        desktop_width: u16,
        /// Actual desktop height negotiated with server.
        desktop_height: u16,
        /// Error message if success is false.
        error: Option<String>,
    },

    /// Bitmap region update from RDP session (ProxyRdp -> Web).
    /// Contains a PNG-encoded image of the updated screen region.
    RdpDisplayUpdate {
        session_id: String,
        /// X coordinate of the updated region.
        x: u16,
        /// Y coordinate of the updated region.
        y: u16,
        /// Width of the updated region.
        width: u16,
        /// Height of the updated region.
        height: u16,
        /// PNG-encoded bitmap data for the region.
        png_data: Vec<u8>,
    },

    /// Input event from browser to RDP session (Web -> ProxyRdp).
    RdpInput {
        session_id: String,
        input: RdpInputEvent,
    },

    /// Desktop resize request (Web -> ProxyRdp).
    RdpResize {
        session_id: String,
        width: u16,
        height: u16,
    },

    /// Desktop size changed notification (ProxyRdp -> Web).
    /// Sent after a successful resize (DeactivateAll/Reactivation).
    RdpDesktopResize {
        session_id: String,
        width: u16,
        height: u16,
    },

    /// H.264 encoded video frame (ProxyRdp -> Web).
    /// Can also be forwarded to vauban-audit for session recording.
    RdpVideoFrame {
        session_id: String,
        /// Monotonic timestamp in microseconds from session start.
        timestamp_us: u64,
        /// true = I-frame (keyframe), false = P-frame (delta).
        is_keyframe: bool,
        /// Frame dimensions (can change after resize).
        width: u16,
        height: u16,
        /// H.264 NAL unit(s) for this frame.
        data: Vec<u8>,
    },

    /// Enable or disable H.264 video mode for a session (Web -> ProxyRdp).
    ///
    /// The encoder bitrate is configured at the proxy level via the supervisor
    /// (VAUBAN_RDP_VIDEO_BITRATE_BPS), not through this message.
    RdpSetVideoMode {
        session_id: String,
        enabled: bool,
    },

    /// Request to close an RDP session.
    RdpSessionClose {
        session_id: String,
    },

    // ========== TCP Connection Brokering (Web -> Supervisor -> Proxy) ==========
    /// Request supervisor to establish a TCP connection on behalf of the sandboxed proxy.
    ///
    /// The supervisor performs DNS resolution and TCP connect, then passes the
    /// connected socket FD to the proxy via SCM_RIGHTS over a Unix socket pair.
    /// This allows sandboxed processes (Capsicum) to receive pre-established connections
    /// without requiring network access.
    TcpConnectRequest {
        request_id: u64,
        /// Session ID to correlate the FD with subsequent SshSessionOpen.
        session_id: String,
        /// Target hostname (DNS resolution performed by supervisor).
        host: String,
        /// Target port.
        port: u16,
        /// Target service that will receive the FD (e.g., Service::ProxySsh, Service::ProxyRdp).
        target_service: Service,
    },

    /// Response from supervisor after establishing (or failing) TCP connection.
    ///
    /// If success is true, the FD has been sent to the target service via SCM_RIGHTS.
    /// The target service should have already received the FD before this message arrives.
    TcpConnectResponse {
        request_id: u64,
        session_id: String,
        success: bool,
        /// Error message if connection failed (DNS resolution, connection refused, etc.).
        error: Option<String>,
    },
}

impl Message {
    /// Get the request ID if this message has one.
    pub fn request_id(&self) -> Option<u64> {
        match self {
            Message::AuthRequest { request_id, .. }
            | Message::AuthResponse { request_id, .. }
            | Message::MfaVerify { request_id, .. }
            | Message::MfaVerifyResponse { request_id, .. }
            | Message::RbacCheck { request_id, .. }
            | Message::RbacResponse { request_id, .. }
            | Message::VaultGetSecret { request_id, .. }
            | Message::VaultSecretResponse { request_id, .. }
            | Message::VaultGetCredential { request_id, .. }
            | Message::VaultCredentialResponse { request_id, .. }
            | Message::VaultEncrypt { request_id, .. }
            | Message::VaultEncryptResponse { request_id, .. }
            | Message::VaultDecrypt { request_id, .. }
            | Message::VaultDecryptResponse { request_id, .. }
            | Message::VaultMfaGenerate { request_id, .. }
            | Message::VaultMfaGenerateResponse { request_id, .. }
            | Message::VaultMfaVerify { request_id, .. }
            | Message::VaultMfaVerifyResponse { request_id, .. }
            | Message::VaultMfaGetSecret { request_id, .. }
            | Message::VaultMfaGetSecretResponse { request_id, .. }
            | Message::SshSessionOpen { request_id, .. }
            | Message::SshSessionOpened { request_id, .. }
            | Message::SshFetchHostKey { request_id, .. }
            | Message::SshHostKeyResult { request_id, .. }
            | Message::RdpSessionOpen { request_id, .. }
            | Message::RdpSessionOpened { request_id, .. }
            | Message::TcpConnectRequest { request_id, .. }
            | Message::TcpConnectResponse { request_id, .. } => Some(*request_id),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    // Helper functions for bincode 3.0 serialization
    fn serialize<T: serde::Serialize>(value: &T) -> Vec<u8> {
        bincode::serde::encode_to_vec(value, bincode::config::standard()).unwrap()
    }

    fn deserialize<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> T {
        let (value, _): (T, _) =
            bincode::serde::decode_from_slice(bytes, bincode::config::standard()).unwrap();
        value
    }

    // ==================== Service Tests ====================

    #[test]
    fn test_service_enum_variants() {
        let services = [
            Service::Supervisor,
            Service::Web,
            Service::Auth,
            Service::Rbac,
            Service::Vault,
            Service::Audit,
            Service::ProxySsh,
            Service::ProxyRdp,
        ];
        assert_eq!(services.len(), 8);
    }

    #[test]
    fn test_service_equality() {
        assert_eq!(Service::Web, Service::Web);
        assert_ne!(Service::Web, Service::Auth);
    }

    #[test]
    fn test_service_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(Service::Web);
        set.insert(Service::Auth);
        set.insert(Service::Web); // Duplicate
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_service_serialization() {
        let service = Service::Auth;
        let serialized = serialize(&service);
        let deserialized: Service = deserialize(&serialized);
        assert_eq!(service, deserialized);
    }

    // ==================== ControlMessage Tests ====================

    #[test]
    fn test_control_message_drain() {
        let msg = ControlMessage::Drain;
        let serialized = serialize(&msg);
        let deserialized: ControlMessage = deserialize(&serialized);
        assert!(matches!(deserialized, ControlMessage::Drain));
    }

    #[test]
    fn test_control_message_drain_complete() {
        let msg = ControlMessage::DrainComplete { pending_requests: 5 };
        let serialized = serialize(&msg);
        let deserialized: ControlMessage = deserialize(&serialized);
        if let ControlMessage::DrainComplete { pending_requests } = deserialized {
            assert_eq!(pending_requests, 5);
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_control_message_ping_pong() {
        let ping = ControlMessage::Ping { seq: 42 };
        let stats = ServiceStats {
            uptime_secs: 100,
            requests_processed: 1000,
            requests_failed: 5,
            active_connections: 10,
            pending_requests: 2,
        };
        let pong = ControlMessage::Pong { seq: 42, stats };

        let ping_serialized = serialize(&ping);
        let pong_serialized = serialize(&pong);

        let ping_deser: ControlMessage = deserialize(&ping_serialized);
        let pong_deser: ControlMessage = deserialize(&pong_serialized);

        if let ControlMessage::Ping { seq } = ping_deser {
            assert_eq!(seq, 42);
        } else {
            panic!("Wrong variant");
        }

        if let ControlMessage::Pong { seq, stats } = pong_deser {
            assert_eq!(seq, 42);
            assert_eq!(stats.uptime_secs, 100);
            assert_eq!(stats.requests_processed, 1000);
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_control_message_shutdown() {
        let msg = ControlMessage::Shutdown;
        let serialized = serialize(&msg);
        let deserialized: ControlMessage = deserialize(&serialized);
        assert!(matches!(deserialized, ControlMessage::Shutdown));
    }

    // ==================== ServiceStats Tests ====================

    #[test]
    fn test_service_stats_default() {
        let stats = ServiceStats::default();
        assert_eq!(stats.uptime_secs, 0);
        assert_eq!(stats.requests_processed, 0);
        assert_eq!(stats.requests_failed, 0);
        assert_eq!(stats.active_connections, 0);
        assert_eq!(stats.pending_requests, 0);
    }

    #[test]
    fn test_service_stats_serialization() {
        let stats = ServiceStats {
            uptime_secs: 3600,
            requests_processed: 10000,
            requests_failed: 50,
            active_connections: 25,
            pending_requests: 3,
        };
        let serialized = serialize(&stats);
        let deserialized: ServiceStats = deserialize(&serialized);
        assert_eq!(stats.uptime_secs, deserialized.uptime_secs);
        assert_eq!(stats.requests_processed, deserialized.requests_processed);
    }

    // ==================== AuthResult Tests ====================

    #[test]
    fn test_auth_result_success() {
        let result = AuthResult::Success {
            user_id: "user123".to_string(),
            session_id: "sess456".to_string(),
            roles: vec!["admin".to_string(), "user".to_string()],
        };
        let serialized = serialize(&result);
        let deserialized: AuthResult = deserialize(&serialized);
        if let AuthResult::Success { user_id, roles, .. } = deserialized {
            assert_eq!(user_id, "user123");
            assert_eq!(roles.len(), 2);
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_auth_result_failure() {
        let result = AuthResult::Failure {
            reason: "Invalid password".to_string(),
        };
        let serialized = serialize(&result);
        let deserialized: AuthResult = deserialize(&serialized);
        if let AuthResult::Failure { reason } = deserialized {
            assert_eq!(reason, "Invalid password");
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_auth_result_mfa_required() {
        let result = AuthResult::MfaRequired {
            challenge_id: "chal789".to_string(),
        };
        let serialized = serialize(&result);
        let deserialized: AuthResult = deserialize(&serialized);
        if let AuthResult::MfaRequired { challenge_id } = deserialized {
            assert_eq!(challenge_id, "chal789");
        } else {
            panic!("Wrong variant");
        }
    }

    // ==================== RbacResult Tests ====================

    #[test]
    fn test_rbac_result_allowed() {
        let result = RbacResult {
            allowed: true,
            reason: None,
        };
        let serialized = serialize(&result);
        let deserialized: RbacResult = deserialize(&serialized);
        assert!(deserialized.allowed);
        assert!(deserialized.reason.is_none());
    }

    #[test]
    fn test_rbac_result_denied_with_reason() {
        let result = RbacResult {
            allowed: false,
            reason: Some("Insufficient permissions".to_string()),
        };
        let serialized = serialize(&result);
        let deserialized: RbacResult = deserialize(&serialized);
        assert!(!deserialized.allowed);
        assert_eq!(deserialized.reason.unwrap(), "Insufficient permissions");
    }

    // ==================== AuditEventType Tests ====================

    #[test]
    fn test_audit_event_types() {
        let events = [
            AuditEventType::AuthSuccess,
            AuditEventType::AuthFailure,
            AuditEventType::SessionStart,
            AuditEventType::SessionEnd,
            AuditEventType::CommandExecuted,
            AuditEventType::AccessDenied,
            AuditEventType::PolicyChange,
        ];
        assert_eq!(events.len(), 7);

        for event in events {
            let serialized = serialize(&event);
            let _: AuditEventType = deserialize(&serialized);
        }
    }

    // ==================== Message Tests ====================

    #[test]
    fn test_message_control() {
        let msg = Message::Control(ControlMessage::Ping { seq: 1 });
        assert!(msg.request_id().is_none());
    }

    #[test]
    fn test_message_auth_request() {
        let msg = Message::AuthRequest {
            request_id: 100,
            username: "testuser".to_string(),
            credential: vec![1, 2, 3, 4],
            source_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        };
        assert_eq!(msg.request_id(), Some(100));
        
        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::AuthRequest { username, source_ip, .. } = deserialized {
            assert_eq!(username, "testuser");
            assert_eq!(source_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_rbac_check() {
        let msg = Message::RbacCheck {
            request_id: 200,
            subject: "user:alice".to_string(),
            object: "asset:server1".to_string(),
            action: "ssh".to_string(),
        };
        assert_eq!(msg.request_id(), Some(200));
    }

    #[test]
    fn test_message_vault_get_secret() {
        let msg = Message::VaultGetSecret {
            request_id: 300,
            path: "/secrets/db/password".to_string(),
        };
        assert_eq!(msg.request_id(), Some(300));
    }

    #[test]
    fn test_message_vault_secret_response_with_data() {
        let msg = Message::VaultSecretResponse {
            request_id: 300,
            data: Some(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        };
        assert_eq!(msg.request_id(), Some(300));
    }

    #[test]
    fn test_message_vault_secret_response_not_found() {
        let msg = Message::VaultSecretResponse {
            request_id: 301,
            data: None,
        };
        assert_eq!(msg.request_id(), Some(301));
    }

    #[test]
    fn test_message_audit_event() {
        let msg = Message::AuditEvent {
            timestamp: 1706140800,
            event_type: AuditEventType::SessionStart,
            user_id: Some("alice".to_string()),
            session_id: Some("sess123".to_string()),
            source_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            details: "SSH session started".to_string(),
        };
        // AuditEvent has no request_id
        assert!(msg.request_id().is_none());
    }

    #[test]
    fn test_message_session_recording_chunk() {
        let msg = Message::SessionRecordingChunk {
            session_id: "sess123".to_string(),
            sequence: 42,
            data: vec![0; 1024],
        };
        // SessionRecordingChunk has no request_id
        assert!(msg.request_id().is_none());
        
        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::SessionRecordingChunk { session_id, sequence, data } = deserialized {
            assert_eq!(session_id, "sess123");
            assert_eq!(sequence, 42);
            assert_eq!(data.len(), 1024);
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_mfa_verify() {
        let msg = Message::MfaVerify {
            request_id: 400,
            challenge_id: "chal123".to_string(),
            code: "123456".to_string(),
        };
        assert_eq!(msg.request_id(), Some(400));
    }

    #[test]
    fn test_message_mfa_verify_response_success() {
        let msg = Message::MfaVerifyResponse {
            request_id: 400,
            success: true,
            session_id: Some("sess456".to_string()),
        };
        assert_eq!(msg.request_id(), Some(400));
    }

    #[test]
    fn test_message_mfa_verify_response_failure() {
        let msg = Message::MfaVerifyResponse {
            request_id: 401,
            success: false,
            session_id: None,
        };
        assert_eq!(msg.request_id(), Some(401));
    }

    // ==================== Serialization Size Tests ====================

    #[test]
    fn test_message_serialization_size_ping() {
        let msg = Message::Control(ControlMessage::Ping { seq: u64::MAX });
        let serialized = serialize(&msg);
        // Ping should be small
        assert!(serialized.len() < 32);
    }

    #[test]
    fn test_message_serialization_roundtrip_all_variants() {
        let messages: Vec<Message> = vec![
            Message::Control(ControlMessage::Drain),
            Message::Control(ControlMessage::Shutdown),
            Message::AuthRequest {
                request_id: 1,
                username: "test".to_string(),
                credential: vec![],
                source_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            },
            Message::AuthResponse {
                request_id: 1,
                result: AuthResult::Failure { reason: "test".to_string() },
            },
            Message::RbacCheck {
                request_id: 2,
                subject: "s".to_string(),
                object: "o".to_string(),
                action: "a".to_string(),
            },
            Message::RbacResponse {
                request_id: 2,
                result: RbacResult { allowed: true, reason: None },
            },
            Message::AuditAck { timestamp: 12345 },
        ];

        for msg in messages {
            let serialized = serialize(&msg);
            let deserialized: Message = deserialize(&serialized);
            // Just verify it doesn't panic
            let _ = deserialized.request_id();
        }
    }

    // ==================== SSH Session Message Tests ====================

    #[test]
    fn test_message_ssh_session_open() {
        let msg = Message::SshSessionOpen {
            request_id: 500,
            session_id: "sess-uuid-123".to_string(),
            user_id: "user-uuid-456".to_string(),
            asset_id: "asset-uuid-789".to_string(),
            asset_host: "192.168.1.100".to_string(),
            asset_port: 22,
            username: "admin".to_string(),
            terminal_cols: 80,
            terminal_rows: 24,
            auth_type: "password".to_string(),
            password: Some(SensitiveString::new("secret123".to_string())),
            private_key: None,
            passphrase: None,
            expected_host_key: Some("ssh-ed25519 AAAA...".to_string()),
        };
        assert_eq!(msg.request_id(), Some(500));

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::SshSessionOpen {
            request_id,
            session_id,
            user_id,
            asset_host,
            asset_port,
            username,
            terminal_cols,
            terminal_rows,
            auth_type,
            password,
            ..
        } = deserialized
        {
            assert_eq!(request_id, 500);
            assert_eq!(session_id, "sess-uuid-123");
            assert_eq!(user_id, "user-uuid-456");
            assert_eq!(asset_host, "192.168.1.100");
            assert_eq!(asset_port, 22);
            assert_eq!(username, "admin");
            assert_eq!(terminal_cols, 80);
            assert_eq!(terminal_rows, 24);
            assert_eq!(auth_type, "password");
            assert_eq!(password.as_ref().map(|s| s.as_str()), Some("secret123"));
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_ssh_session_opened_success() {
        let msg = Message::SshSessionOpened {
            request_id: 500,
            session_id: "sess-uuid-123".to_string(),
            success: true,
            error: None,
        };
        assert_eq!(msg.request_id(), Some(500));

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::SshSessionOpened {
            success, error, ..
        } = deserialized
        {
            assert!(success);
            assert!(error.is_none());
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_ssh_session_opened_failure() {
        let msg = Message::SshSessionOpened {
            request_id: 501,
            session_id: "sess-uuid-123".to_string(),
            success: false,
            error: Some("Connection refused".to_string()),
        };
        assert_eq!(msg.request_id(), Some(501));

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::SshSessionOpened {
            success, error, ..
        } = deserialized
        {
            assert!(!success);
            assert_eq!(error, Some("Connection refused".to_string()));
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_ssh_data() {
        let msg = Message::SshData {
            session_id: "sess-uuid-123".to_string(),
            data: vec![0x1b, 0x5b, 0x48], // ESC[H - cursor home
        };
        // SshData has no request_id
        assert!(msg.request_id().is_none());

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::SshData { session_id, data } = deserialized {
            assert_eq!(session_id, "sess-uuid-123");
            assert_eq!(data, vec![0x1b, 0x5b, 0x48]);
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_ssh_session_close() {
        let msg = Message::SshSessionClose {
            session_id: "sess-uuid-123".to_string(),
        };
        // SshSessionClose has no request_id
        assert!(msg.request_id().is_none());

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::SshSessionClose { session_id } = deserialized {
            assert_eq!(session_id, "sess-uuid-123");
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_ssh_resize() {
        let msg = Message::SshResize {
            session_id: "sess-uuid-123".to_string(),
            cols: 120,
            rows: 40,
        };
        // SshResize has no request_id
        assert!(msg.request_id().is_none());

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::SshResize {
            session_id,
            cols,
            rows,
        } = deserialized
        {
            assert_eq!(session_id, "sess-uuid-123");
            assert_eq!(cols, 120);
            assert_eq!(rows, 40);
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_ssh_messages_serialization_roundtrip() {
        let messages: Vec<Message> = vec![
            Message::SshSessionOpen {
                request_id: 1,
                session_id: "s1".to_string(),
                user_id: "u1".to_string(),
                asset_id: "a1".to_string(),
                asset_host: "host".to_string(),
                asset_port: 22,
                username: "user".to_string(),
                terminal_cols: 80,
                terminal_rows: 24,
                auth_type: "password".to_string(),
                password: Some(SensitiveString::new("pass".to_string())),
                private_key: None,
                passphrase: None,
                expected_host_key: None,
            },
            Message::SshSessionOpened {
                request_id: 1,
                session_id: "s1".to_string(),
                success: true,
                error: None,
            },
            Message::SshData {
                session_id: "s1".to_string(),
                data: b"hello".to_vec(),
            },
            Message::SshResize {
                session_id: "s1".to_string(),
                cols: 100,
                rows: 30,
            },
            Message::SshSessionClose {
                session_id: "s1".to_string(),
            },
        ];

        for msg in messages {
            let serialized = serialize(&msg);
            let deserialized: Message = deserialize(&serialized);
            // Just verify it doesn't panic
            let _ = deserialized.request_id();
        }
    }

    // ==================== TCP Connection Brokering Tests ====================

    #[test]
    fn test_message_tcp_connect_request() {
        let msg = Message::TcpConnectRequest {
            request_id: 600,
            session_id: "sess-tcp-123".to_string(),
            host: "example.com".to_string(),
            port: 22,
            target_service: Service::ProxySsh,
        };
        assert_eq!(msg.request_id(), Some(600));

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::TcpConnectRequest {
            request_id,
            session_id,
            host,
            port,
            target_service,
        } = deserialized
        {
            assert_eq!(request_id, 600);
            assert_eq!(session_id, "sess-tcp-123");
            assert_eq!(host, "example.com");
            assert_eq!(port, 22);
            assert_eq!(target_service, Service::ProxySsh);
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_tcp_connect_response_success() {
        let msg = Message::TcpConnectResponse {
            request_id: 600,
            session_id: "sess-tcp-123".to_string(),
            success: true,
            error: None,
        };
        assert_eq!(msg.request_id(), Some(600));

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::TcpConnectResponse {
            request_id,
            success,
            error,
            ..
        } = deserialized
        {
            assert_eq!(request_id, 600);
            assert!(success);
            assert!(error.is_none());
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_tcp_connect_response_failure() {
        let msg = Message::TcpConnectResponse {
            request_id: 601,
            session_id: "sess-tcp-456".to_string(),
            success: false,
            error: Some("DNS resolution failed: unknown host".to_string()),
        };
        assert_eq!(msg.request_id(), Some(601));

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::TcpConnectResponse {
            success, error, ..
        } = deserialized
        {
            assert!(!success);
            assert_eq!(error, Some("DNS resolution failed: unknown host".to_string()));
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_tcp_connect_messages_serialization_roundtrip() {
        let messages: Vec<Message> = vec![
            Message::TcpConnectRequest {
                request_id: 1,
                session_id: "s1".to_string(),
                host: "192.168.1.100".to_string(),
                port: 22,
                target_service: Service::ProxySsh,
            },
            Message::TcpConnectRequest {
                request_id: 2,
                session_id: "s2".to_string(),
                host: "rdp-server.internal".to_string(),
                port: 3389,
                target_service: Service::ProxyRdp,
            },
            Message::TcpConnectResponse {
                request_id: 1,
                session_id: "s1".to_string(),
                success: true,
                error: None,
            },
            Message::TcpConnectResponse {
                request_id: 2,
                session_id: "s2".to_string(),
                success: false,
                error: Some("Connection refused".to_string()),
            },
        ];

        for msg in messages {
            let serialized = serialize(&msg);
            let deserialized: Message = deserialize(&serialized);
            // Verify request_id extraction works
            assert!(deserialized.request_id().is_some());
        }
    }

    // ==================== SSH Host Key Message Tests ====================

    #[test]
    fn test_message_ssh_fetch_host_key() {
        let msg = Message::SshFetchHostKey {
            request_id: 700,
            asset_host: "10.0.0.1".to_string(),
            asset_port: 22,
        };
        assert_eq!(msg.request_id(), Some(700));

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::SshFetchHostKey {
            request_id,
            asset_host,
            asset_port,
        } = deserialized
        {
            assert_eq!(request_id, 700);
            assert_eq!(asset_host, "10.0.0.1");
            assert_eq!(asset_port, 22);
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_ssh_host_key_result_success() {
        let msg = Message::SshHostKeyResult {
            request_id: 700,
            success: true,
            host_key: Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA".to_string()),
            key_fingerprint: Some("SHA256:abcdef123456".to_string()),
            error: None,
        };
        assert_eq!(msg.request_id(), Some(700));

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::SshHostKeyResult {
            success,
            host_key,
            key_fingerprint,
            error,
            ..
        } = deserialized
        {
            assert!(success);
            assert!(host_key.unwrap().contains("ssh-ed25519"));
            assert!(key_fingerprint.unwrap().contains("SHA256"));
            assert!(error.is_none());
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_ssh_host_key_result_failure() {
        let msg = Message::SshHostKeyResult {
            request_id: 701,
            success: false,
            host_key: None,
            key_fingerprint: None,
            error: Some("Connection refused".to_string()),
        };
        assert_eq!(msg.request_id(), Some(701));

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::SshHostKeyResult {
            success, error, ..
        } = deserialized
        {
            assert!(!success);
            assert_eq!(error, Some("Connection refused".to_string()));
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_ssh_session_open_with_host_key() {
        let msg = Message::SshSessionOpen {
            request_id: 800,
            session_id: "s1".to_string(),
            user_id: "u1".to_string(),
            asset_id: "a1".to_string(),
            asset_host: "host".to_string(),
            asset_port: 22,
            username: "user".to_string(),
            terminal_cols: 80,
            terminal_rows: 24,
            auth_type: "password".to_string(),
            password: Some(SensitiveString::new("pass".to_string())),
            private_key: None,
            passphrase: None,
            expected_host_key: Some("ssh-ed25519 AAAA...test".to_string()),
        };

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::SshSessionOpen {
            expected_host_key, ..
        } = deserialized
        {
            assert_eq!(
                expected_host_key,
                Some("ssh-ed25519 AAAA...test".to_string())
            );
        } else {
            panic!("Wrong variant");
        }
    }

    // ==================== Vault Crypto Message Tests (M-1, C-2) ====================

    #[test]
    fn test_message_vault_encrypt() {
        let msg = Message::VaultEncrypt {
            request_id: 900,
            domain: "credentials".to_string(),
            plaintext: SensitiveString::new("my-secret-password".to_string()),
        };
        assert_eq!(msg.request_id(), Some(900));

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::VaultEncrypt {
            request_id,
            domain,
            plaintext,
        } = deserialized
        {
            assert_eq!(request_id, 900);
            assert_eq!(domain, "credentials");
            assert_eq!(plaintext.as_str(), "my-secret-password");
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_vault_encrypt_response_success() {
        let msg = Message::VaultEncryptResponse {
            request_id: 900,
            ciphertext: Some("v1:SGVsbG8gV29ybGQ=".to_string()),
            error: None,
        };
        assert_eq!(msg.request_id(), Some(900));
    }

    #[test]
    fn test_message_vault_encrypt_response_error() {
        let msg = Message::VaultEncryptResponse {
            request_id: 901,
            ciphertext: None,
            error: Some("Unknown domain".to_string()),
        };
        assert_eq!(msg.request_id(), Some(901));
    }

    #[test]
    fn test_message_vault_decrypt() {
        let msg = Message::VaultDecrypt {
            request_id: 910,
            domain: "mfa".to_string(),
            ciphertext: "v1:SGVsbG8gV29ybGQ=".to_string(),
        };
        assert_eq!(msg.request_id(), Some(910));
    }

    #[test]
    fn test_message_vault_decrypt_response_success() {
        let msg = Message::VaultDecryptResponse {
            request_id: 910,
            plaintext: Some(SensitiveString::new("decrypted-value".to_string())),
            error: None,
        };
        assert_eq!(msg.request_id(), Some(910));

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::VaultDecryptResponse {
            plaintext, error, ..
        } = deserialized
        {
            assert_eq!(plaintext.as_ref().map(|s| s.as_str()), Some("decrypted-value"));
            assert!(error.is_none());
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_vault_decrypt_response_debug_redacted() {
        let msg = Message::VaultDecryptResponse {
            request_id: 911,
            plaintext: Some(SensitiveString::new("super-secret".to_string())),
            error: None,
        };
        let debug = format!("{:?}", msg);
        assert!(
            !debug.contains("super-secret"),
            "VaultDecryptResponse Debug must NOT contain plaintext"
        );
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn test_message_vault_mfa_generate() {
        let msg = Message::VaultMfaGenerate {
            request_id: 920,
            username: "alice".to_string(),
            issuer: "VAUBAN".to_string(),
        };
        assert_eq!(msg.request_id(), Some(920));

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::VaultMfaGenerate {
            username, issuer, ..
        } = deserialized
        {
            assert_eq!(username, "alice");
            assert_eq!(issuer, "VAUBAN");
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_vault_mfa_generate_response() {
        let msg = Message::VaultMfaGenerateResponse {
            request_id: 920,
            encrypted_secret: Some("v1:encrypted".to_string()),
            plaintext_secret: Some(SensitiveString::new("JBSWY3DPEHPK3PXP".to_string())),
            error: None,
        };
        assert_eq!(msg.request_id(), Some(920));
    }

    #[test]
    fn test_message_vault_mfa_verify() {
        let msg = Message::VaultMfaVerify {
            request_id: 930,
            encrypted_secret: "v1:encrypted-totp".to_string(),
            code: "123456".to_string(),
        };
        assert_eq!(msg.request_id(), Some(930));
    }

    #[test]
    fn test_message_vault_mfa_verify_response() {
        let msg = Message::VaultMfaVerifyResponse {
            request_id: 930,
            valid: true,
            error: None,
        };
        assert_eq!(msg.request_id(), Some(930));

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::VaultMfaVerifyResponse { valid, error, .. } = deserialized {
            assert!(valid);
            assert!(error.is_none());
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_vault_mfa_get_secret() {
        let msg = Message::VaultMfaGetSecret {
            request_id: 940,
            encrypted_secret: "v1:encrypted-totp".to_string(),
        };
        assert_eq!(msg.request_id(), Some(940));
    }

    #[test]
    fn test_message_vault_mfa_get_secret_response() {
        let msg = Message::VaultMfaGetSecretResponse {
            request_id: 940,
            plaintext_secret: Some(SensitiveString::new("JBSWY3DPEHPK3PXP".to_string())),
            error: None,
        };
        assert_eq!(msg.request_id(), Some(940));
    }

    #[test]
    fn test_vault_crypto_messages_serialization_roundtrip() {
        let messages: Vec<Message> = vec![
            Message::VaultEncrypt {
                request_id: 1,
                domain: "credentials".to_string(),
                plaintext: SensitiveString::new("secret".to_string()),
            },
            Message::VaultEncryptResponse {
                request_id: 1,
                ciphertext: Some("v1:abc".to_string()),
                error: None,
            },
            Message::VaultDecrypt {
                request_id: 2,
                domain: "mfa".to_string(),
                ciphertext: "v1:abc".to_string(),
            },
            Message::VaultDecryptResponse {
                request_id: 2,
                plaintext: Some(SensitiveString::new("secret".to_string())),
                error: None,
            },
            Message::VaultMfaGenerate {
                request_id: 3,
                username: "user".to_string(),
                issuer: "VAUBAN".to_string(),
            },
            Message::VaultMfaGenerateResponse {
                request_id: 3,
                encrypted_secret: Some("v1:enc".to_string()),
                plaintext_secret: Some(SensitiveString::new("JBSWY3DPEHPK3PXP".to_string())),
                error: None,
            },
            Message::VaultMfaVerify {
                request_id: 4,
                encrypted_secret: "v1:enc".to_string(),
                code: "123456".to_string(),
            },
            Message::VaultMfaVerifyResponse {
                request_id: 4,
                valid: true,
                error: None,
            },
            Message::VaultMfaGetSecret {
                request_id: 5,
                encrypted_secret: "v1:enc".to_string(),
            },
            Message::VaultMfaGetSecretResponse {
                request_id: 5,
                plaintext_secret: Some(SensitiveString::new("JBSWY3DPEHPK3PXP".to_string())),
                error: None,
            },
        ];

        for msg in messages {
            let serialized = serialize(&msg);
            let deserialized: Message = deserialize(&serialized);
            assert!(deserialized.request_id().is_some());
        }
    }

    #[test]
    fn test_message_vault_encrypt_debug_redacts_plaintext() {
        let msg = Message::VaultEncrypt {
            request_id: 950,
            domain: "credentials".to_string(),
            plaintext: SensitiveString::new("top-secret-password".to_string()),
        };
        let debug = format!("{:?}", msg);
        assert!(
            !debug.contains("top-secret-password"),
            "VaultEncrypt Debug must NOT contain plaintext"
        );
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn test_message_ssh_session_open_without_host_key() {
        let msg = Message::SshSessionOpen {
            request_id: 801,
            session_id: "s1".to_string(),
            user_id: "u1".to_string(),
            asset_id: "a1".to_string(),
            asset_host: "host".to_string(),
            asset_port: 22,
            username: "user".to_string(),
            terminal_cols: 80,
            terminal_rows: 24,
            auth_type: "password".to_string(),
            password: Some(SensitiveString::new("pass".to_string())),
            private_key: None,
            passphrase: None,
            expected_host_key: None,
        };

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::SshSessionOpen {
            expected_host_key, ..
        } = deserialized
        {
            assert!(expected_host_key.is_none());
        } else {
            panic!("Wrong variant");
        }
    }

    // ==================== RDP Messages Tests ====================

    #[test]
    fn test_message_rdp_session_open() {
        let msg = Message::RdpSessionOpen {
            request_id: 700,
            session_id: "rdp-sess-123".to_string(),
            user_id: "user-uuid-456".to_string(),
            asset_id: "asset-uuid-789".to_string(),
            asset_host: "10.0.0.50".to_string(),
            asset_port: 3389,
            username: "administrator".to_string(),
            password: Some(SensitiveString::new("rdp-secret".to_string())),
            domain: Some("WORKGROUP".to_string()),
            desktop_width: 1920,
            desktop_height: 1080,
        };
        assert_eq!(msg.request_id(), Some(700));

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::RdpSessionOpen {
            request_id,
            session_id,
            user_id,
            asset_host,
            asset_port,
            username,
            password,
            domain,
            desktop_width,
            desktop_height,
            ..
        } = deserialized
        {
            assert_eq!(request_id, 700);
            assert_eq!(session_id, "rdp-sess-123");
            assert_eq!(user_id, "user-uuid-456");
            assert_eq!(asset_host, "10.0.0.50");
            assert_eq!(asset_port, 3389);
            assert_eq!(username, "administrator");
            assert_eq!(password.as_ref().map(|s| s.as_str()), Some("rdp-secret"));
            assert_eq!(domain.as_deref(), Some("WORKGROUP"));
            assert_eq!(desktop_width, 1920);
            assert_eq!(desktop_height, 1080);
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_rdp_session_open_no_domain() {
        let msg = Message::RdpSessionOpen {
            request_id: 701,
            session_id: "rdp-no-dom".to_string(),
            user_id: "u1".to_string(),
            asset_id: "a1".to_string(),
            asset_host: "host".to_string(),
            asset_port: 3389,
            username: "user".to_string(),
            password: None,
            domain: None,
            desktop_width: 1280,
            desktop_height: 720,
        };

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::RdpSessionOpen {
            password, domain, ..
        } = deserialized
        {
            assert!(password.is_none());
            assert!(domain.is_none());
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_rdp_session_opened_success() {
        let msg = Message::RdpSessionOpened {
            request_id: 700,
            session_id: "rdp-sess-123".to_string(),
            success: true,
            desktop_width: 1920,
            desktop_height: 1080,
            error: None,
        };
        assert_eq!(msg.request_id(), Some(700));

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::RdpSessionOpened {
            success,
            desktop_width,
            desktop_height,
            error,
            ..
        } = deserialized
        {
            assert!(success);
            assert_eq!(desktop_width, 1920);
            assert_eq!(desktop_height, 1080);
            assert!(error.is_none());
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_rdp_session_opened_failure() {
        let msg = Message::RdpSessionOpened {
            request_id: 700,
            session_id: "rdp-sess-123".to_string(),
            success: false,
            desktop_width: 0,
            desktop_height: 0,
            error: Some("Authentication failed".to_string()),
        };

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::RdpSessionOpened {
            success, error, ..
        } = deserialized
        {
            assert!(!success);
            assert_eq!(error.as_deref(), Some("Authentication failed"));
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_rdp_display_update() {
        let png_data = vec![0x89, 0x50, 0x4E, 0x47]; // PNG magic bytes
        let msg = Message::RdpDisplayUpdate {
            session_id: "rdp-sess-123".to_string(),
            x: 100,
            y: 200,
            width: 640,
            height: 480,
            png_data: png_data.clone(),
        };

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::RdpDisplayUpdate {
            session_id,
            x,
            y,
            width,
            height,
            png_data: data,
        } = deserialized
        {
            assert_eq!(session_id, "rdp-sess-123");
            assert_eq!(x, 100);
            assert_eq!(y, 200);
            assert_eq!(width, 640);
            assert_eq!(height, 480);
            assert_eq!(data, png_data);
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_rdp_video_frame() {
        let h264_data = vec![0x00, 0x00, 0x00, 0x01, 0x67, 0x42]; // NAL start code + SPS
        let msg = Message::RdpVideoFrame {
            session_id: "rdp-vid-123".to_string(),
            timestamp_us: 16666,
            is_keyframe: true,
            width: 1920,
            height: 1080,
            data: h264_data.clone(),
        };

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::RdpVideoFrame {
            session_id,
            timestamp_us,
            is_keyframe,
            width,
            height,
            data,
        } = deserialized
        {
            assert_eq!(session_id, "rdp-vid-123");
            assert_eq!(timestamp_us, 16666);
            assert!(is_keyframe);
            assert_eq!(width, 1920);
            assert_eq!(height, 1080);
            assert_eq!(data, h264_data);
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_rdp_video_frame_delta() {
        let msg = Message::RdpVideoFrame {
            session_id: "s1".to_string(),
            timestamp_us: 33333,
            is_keyframe: false,
            width: 1280,
            height: 720,
            data: vec![0x00, 0x00, 0x01, 0x41],
        };

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::RdpVideoFrame {
            is_keyframe,
            timestamp_us,
            ..
        } = deserialized
        {
            assert!(!is_keyframe);
            assert_eq!(timestamp_us, 33333);
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_rdp_input_mouse_move() {
        let msg = Message::RdpInput {
            session_id: "rdp-sess".to_string(),
            input: RdpInputEvent::MouseMove { x: 500, y: 300 },
        };

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::RdpInput { session_id, input } = deserialized {
            assert_eq!(session_id, "rdp-sess");
            if let RdpInputEvent::MouseMove { x, y } = input {
                assert_eq!(x, 500);
                assert_eq!(y, 300);
            } else {
                panic!("Wrong input variant");
            }
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_rdp_input_key_pressed() {
        let msg = Message::RdpInput {
            session_id: "rdp-sess".to_string(),
            input: RdpInputEvent::KeyPressed { scancode: 0x1E },
        };

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::RdpInput { input, .. } = deserialized {
            if let RdpInputEvent::KeyPressed { scancode } = input {
                assert_eq!(scancode, 0x1E); // 'A' key
            } else {
                panic!("Wrong input variant");
            }
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_rdp_input_keyboard_high_level() {
        let msg = Message::RdpInput {
            session_id: "rdp-sess".to_string(),
            input: RdpInputEvent::Keyboard {
                code: "KeyA".to_string(),
                key: "a".to_string(),
                pressed: true,
                shift: false,
                ctrl: false,
                alt: false,
                meta: false,
            },
        };

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::RdpInput { input, .. } = deserialized {
            if let RdpInputEvent::Keyboard {
                code,
                key,
                pressed,
                shift,
                ctrl,
                alt,
                meta,
            } = input
            {
                assert_eq!(code, "KeyA");
                assert_eq!(key, "a");
                assert!(pressed);
                assert!(!shift);
                assert!(!ctrl);
                assert!(!alt);
                assert!(!meta);
            } else {
                panic!("Wrong input variant");
            }
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_rdp_input_mouse_button_high_level() {
        let msg = Message::RdpInput {
            session_id: "rdp-sess".to_string(),
            input: RdpInputEvent::MouseButton {
                button: 0,
                pressed: true,
                x: 100,
                y: 200,
            },
        };

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::RdpInput { input, .. } = deserialized {
            if let RdpInputEvent::MouseButton {
                button,
                pressed,
                x,
                y,
            } = input
            {
                assert_eq!(button, 0);
                assert!(pressed);
                assert_eq!(x, 100);
                assert_eq!(y, 200);
            } else {
                panic!("Wrong input variant");
            }
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_rdp_input_mouse_wheel_high_level() {
        let msg = Message::RdpInput {
            session_id: "rdp-sess".to_string(),
            input: RdpInputEvent::MouseWheel {
                delta_x: 0,
                delta_y: -120,
            },
        };

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::RdpInput { input, .. } = deserialized {
            if let RdpInputEvent::MouseWheel { delta_x, delta_y } = input {
                assert_eq!(delta_x, 0);
                assert_eq!(delta_y, -120);
            } else {
                panic!("Wrong input variant");
            }
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_rdp_resize() {
        let msg = Message::RdpResize {
            session_id: "rdp-sess".to_string(),
            width: 1920,
            height: 1080,
        };

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::RdpResize {
            session_id,
            width,
            height,
        } = deserialized
        {
            assert_eq!(session_id, "rdp-sess");
            assert_eq!(width, 1920);
            assert_eq!(height, 1080);
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_rdp_set_video_mode() {
        let msg = Message::RdpSetVideoMode {
            session_id: "rdp-sess-456".to_string(),
            enabled: true,
        };

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::RdpSetVideoMode {
            session_id,
            enabled,
        } = deserialized
        {
            assert_eq!(session_id, "rdp-sess-456");
            assert!(enabled);
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_rdp_set_video_mode_disabled() {
        let msg = Message::RdpSetVideoMode {
            session_id: "rdp-sess-789".to_string(),
            enabled: false,
        };

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::RdpSetVideoMode {
            enabled,
            ..
        } = deserialized
        {
            assert!(!enabled);
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_message_rdp_session_close() {
        let msg = Message::RdpSessionClose {
            session_id: "rdp-sess-123".to_string(),
        };

        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::RdpSessionClose { session_id } = deserialized {
            assert_eq!(session_id, "rdp-sess-123");
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_rdp_messages_serialization_roundtrip() {
        let messages: Vec<Message> = vec![
            Message::RdpSessionOpen {
                request_id: 1,
                session_id: "s1".to_string(),
                user_id: "u1".to_string(),
                asset_id: "a1".to_string(),
                asset_host: "host".to_string(),
                asset_port: 3389,
                username: "user".to_string(),
                password: Some(SensitiveString::new("pass".to_string())),
                domain: Some("DOMAIN".to_string()),
                desktop_width: 1280,
                desktop_height: 720,
            },
            Message::RdpSessionOpened {
                request_id: 1,
                session_id: "s1".to_string(),
                success: true,
                desktop_width: 1280,
                desktop_height: 720,
                error: None,
            },
            Message::RdpDisplayUpdate {
                session_id: "s1".to_string(),
                x: 0,
                y: 0,
                width: 100,
                height: 100,
                png_data: vec![1, 2, 3],
            },
            Message::RdpInput {
                session_id: "s1".to_string(),
                input: RdpInputEvent::MouseMove { x: 10, y: 20 },
            },
            Message::RdpResize {
                session_id: "s1".to_string(),
                width: 1920,
                height: 1080,
            },
            Message::RdpVideoFrame {
                session_id: "s1".to_string(),
                timestamp_us: 16666,
                is_keyframe: true,
                width: 1920,
                height: 1080,
                data: vec![0, 0, 0, 1],
            },
            Message::RdpSessionClose {
                session_id: "s1".to_string(),
            },
        ];

        for msg in messages {
            let serialized = serialize(&msg);
            let deserialized: Message = deserialize(&serialized);
            let _ = deserialized.request_id();
        }
    }

    #[test]
    fn test_rdp_input_event_all_variants_serialize() {
        let events = vec![
            RdpInputEvent::KeyPressed { scancode: 0x1E },
            RdpInputEvent::KeyReleased { scancode: 0x1E },
            RdpInputEvent::MouseMove { x: 100, y: 200 },
            RdpInputEvent::MouseButtonPressed { button: 0 },
            RdpInputEvent::MouseButtonReleased { button: 2 },
            RdpInputEvent::WheelScroll {
                vertical: true,
                amount: 120,
            },
            RdpInputEvent::MouseButton {
                button: 1,
                pressed: true,
                x: 50,
                y: 60,
            },
            RdpInputEvent::MouseWheel {
                delta_x: 10,
                delta_y: -20,
            },
            RdpInputEvent::Keyboard {
                code: "Enter".to_string(),
                key: "Enter".to_string(),
                pressed: true,
                shift: false,
                ctrl: true,
                alt: false,
                meta: false,
            },
        ];

        for event in events {
            let serialized = serialize(&event);
            let deserialized: RdpInputEvent = deserialize(&serialized);
            let _ = format!("{:?}", deserialized);
        }
    }

    #[test]
    fn test_message_rdp_session_open_password_redacted_in_debug() {
        let msg = Message::RdpSessionOpen {
            request_id: 900,
            session_id: "debug-rdp".to_string(),
            user_id: "u1".to_string(),
            asset_id: "a1".to_string(),
            asset_host: "host".to_string(),
            asset_port: 3389,
            username: "admin".to_string(),
            password: Some(SensitiveString::new("super-secret-rdp-pwd".to_string())),
            domain: None,
            desktop_width: 1280,
            desktop_height: 720,
        };
        let debug = format!("{:?}", msg);
        assert!(
            !debug.contains("super-secret-rdp-pwd"),
            "H-10: RDP Message Debug must NOT contain password"
        );
        assert!(debug.contains("REDACTED"), "H-10: RDP password must show [REDACTED]");
    }

    // ==================== SensitiveString Tests (H-10) ====================

    #[test]
    fn test_sensitive_string_debug_redacts() {
        let secret = SensitiveString::new("my-password".to_string());
        let debug = format!("{:?}", secret);
        assert_eq!(debug, "[REDACTED]", "SensitiveString Debug must show [REDACTED]");
        assert!(
            !debug.contains("my-password"),
            "SensitiveString Debug must NOT contain the actual secret"
        );
    }

    #[test]
    fn test_sensitive_string_into_inner() {
        let secret = SensitiveString::new("secret-value".to_string());
        let inner = secret.into_inner();
        assert_eq!(inner, "secret-value");
    }

    #[test]
    fn test_sensitive_string_as_str() {
        let secret = SensitiveString::new("hello".to_string());
        assert_eq!(secret.as_str(), "hello");
    }

    #[test]
    fn test_sensitive_string_clone() {
        let original = SensitiveString::new("cloneable".to_string());
        let cloned = original.clone();
        assert_eq!(original.as_str(), cloned.as_str());
    }

    #[test]
    fn test_sensitive_string_partial_eq() {
        let a = SensitiveString::new("same".to_string());
        let b = SensitiveString::new("same".to_string());
        let c = SensitiveString::new("different".to_string());
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_sensitive_string_from_string() {
        let s: SensitiveString = "from-str".into();
        assert_eq!(s.as_str(), "from-str");

        let s2: SensitiveString = String::from("from-string").into();
        assert_eq!(s2.as_str(), "from-string");
    }

    #[test]
    fn test_sensitive_string_serde_roundtrip() {
        let original = SensitiveString::new("serde-test".to_string());
        let serialized = serialize(&original);
        let deserialized: SensitiveString = deserialize(&serialized);
        assert_eq!(deserialized.as_str(), "serde-test");
    }

    #[test]
    fn test_sensitive_string_in_message_debug_redacted() {
        let msg = Message::SshSessionOpen {
            request_id: 999,
            session_id: "debug-test".to_string(),
            user_id: "u1".to_string(),
            asset_id: "a1".to_string(),
            asset_host: "host".to_string(),
            asset_port: 22,
            username: "user".to_string(),
            terminal_cols: 80,
            terminal_rows: 24,
            auth_type: "password".to_string(),
            password: Some(SensitiveString::new("super-secret-pwd".to_string())),
            private_key: Some(SensitiveString::new("-----BEGIN KEY-----".to_string())),
            passphrase: Some(SensitiveString::new("my-passphrase".to_string())),
            expected_host_key: None,
        };
        let debug = format!("{:?}", msg);
        assert!(
            !debug.contains("super-secret-pwd"),
            "H-10: Message Debug must NOT contain password"
        );
        assert!(
            !debug.contains("BEGIN KEY"),
            "H-10: Message Debug must NOT contain private key"
        );
        assert!(
            !debug.contains("my-passphrase"),
            "H-10: Message Debug must NOT contain passphrase"
        );
        assert!(debug.contains("REDACTED"), "H-10: Message Debug must show [REDACTED]");
    }

    #[test]
    fn test_sensitive_string_message_serde_roundtrip() {
        let msg = Message::SshSessionOpen {
            request_id: 1000,
            session_id: "rt-test".to_string(),
            user_id: "u1".to_string(),
            asset_id: "a1".to_string(),
            asset_host: "host".to_string(),
            asset_port: 22,
            username: "user".to_string(),
            terminal_cols: 80,
            terminal_rows: 24,
            auth_type: "password".to_string(),
            password: Some(SensitiveString::new("roundtrip-pwd".to_string())),
            private_key: None,
            passphrase: None,
            expected_host_key: None,
        };
        let serialized = serialize(&msg);
        let deserialized: Message = deserialize(&serialized);
        if let Message::SshSessionOpen { password, .. } = deserialized {
            assert_eq!(
                password.as_ref().map(|s| s.as_str()),
                Some("roundtrip-pwd"),
                "SensitiveString must survive IPC serialization roundtrip"
            );
        } else {
            panic!("Wrong variant");
        }
    }
}
