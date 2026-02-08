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

    /// Generate a new TOTP secret, encrypt it, and return the QR code.
    /// The plaintext secret NEVER leaves the vault process unencrypted.
    VaultMfaGenerate {
        request_id: u64,
        /// Username for the provisioning URI.
        username: String,
        /// Issuer for the provisioning URI (e.g. "VAUBAN").
        issuer: String,
    },
    VaultMfaGenerateResponse {
        request_id: u64,
        /// Encrypted TOTP secret (store in DB as mfa_secret).
        encrypted_secret: Option<String>,
        /// Base64-encoded PNG QR code (display once to user).
        qr_code_base64: Option<String>,
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

    /// Re-generate the QR code from an existing encrypted secret.
    VaultMfaQrCode {
        request_id: u64,
        /// Encrypted TOTP secret as stored in DB.
        encrypted_secret: String,
        /// Username for the provisioning URI.
        username: String,
        /// Issuer for the provisioning URI.
        issuer: String,
    },
    VaultMfaQrCodeResponse {
        request_id: u64,
        /// Base64-encoded PNG QR code.
        qr_code_base64: Option<String>,
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

    // ========== TCP Connection Brokering (Web -> Supervisor -> ProxySsh) ==========
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
        /// Target service that will receive the FD (e.g., Service::ProxySsh).
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
            | Message::VaultMfaQrCode { request_id, .. }
            | Message::VaultMfaQrCodeResponse { request_id, .. }
            | Message::SshSessionOpen { request_id, .. }
            | Message::SshSessionOpened { request_id, .. }
            | Message::SshFetchHostKey { request_id, .. }
            | Message::SshHostKeyResult { request_id, .. }
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
            qr_code_base64: Some("iVBORw0KGgo...".to_string()),
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
    fn test_message_vault_mfa_qr_code() {
        let msg = Message::VaultMfaQrCode {
            request_id: 940,
            encrypted_secret: "v1:encrypted-totp".to_string(),
            username: "bob".to_string(),
            issuer: "VAUBAN".to_string(),
        };
        assert_eq!(msg.request_id(), Some(940));
    }

    #[test]
    fn test_message_vault_mfa_qr_code_response() {
        let msg = Message::VaultMfaQrCodeResponse {
            request_id: 940,
            qr_code_base64: Some("iVBORw0KGgo...".to_string()),
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
                qr_code_base64: Some("base64".to_string()),
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
            Message::VaultMfaQrCode {
                request_id: 5,
                encrypted_secret: "v1:enc".to_string(),
                username: "user".to_string(),
                issuer: "VAUBAN".to_string(),
            },
            Message::VaultMfaQrCodeResponse {
                request_id: 5,
                qr_code_base64: Some("base64".to_string()),
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
