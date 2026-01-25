//! IPC message types for inter-process communication between Vauban services.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

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
            | Message::VaultCredentialResponse { request_id, .. } => Some(*request_id),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

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
        let serialized = bincode::serialize(&service).unwrap();
        let deserialized: Service = bincode::deserialize(&serialized).unwrap();
        assert_eq!(service, deserialized);
    }

    // ==================== ControlMessage Tests ====================

    #[test]
    fn test_control_message_drain() {
        let msg = ControlMessage::Drain;
        let serialized = bincode::serialize(&msg).unwrap();
        let deserialized: ControlMessage = bincode::deserialize(&serialized).unwrap();
        assert!(matches!(deserialized, ControlMessage::Drain));
    }

    #[test]
    fn test_control_message_drain_complete() {
        let msg = ControlMessage::DrainComplete { pending_requests: 5 };
        let serialized = bincode::serialize(&msg).unwrap();
        let deserialized: ControlMessage = bincode::deserialize(&serialized).unwrap();
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

        let ping_serialized = bincode::serialize(&ping).unwrap();
        let pong_serialized = bincode::serialize(&pong).unwrap();

        let ping_deser: ControlMessage = bincode::deserialize(&ping_serialized).unwrap();
        let pong_deser: ControlMessage = bincode::deserialize(&pong_serialized).unwrap();

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
        let serialized = bincode::serialize(&msg).unwrap();
        let deserialized: ControlMessage = bincode::deserialize(&serialized).unwrap();
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
        let serialized = bincode::serialize(&stats).unwrap();
        let deserialized: ServiceStats = bincode::deserialize(&serialized).unwrap();
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
        let serialized = bincode::serialize(&result).unwrap();
        let deserialized: AuthResult = bincode::deserialize(&serialized).unwrap();
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
        let serialized = bincode::serialize(&result).unwrap();
        let deserialized: AuthResult = bincode::deserialize(&serialized).unwrap();
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
        let serialized = bincode::serialize(&result).unwrap();
        let deserialized: AuthResult = bincode::deserialize(&serialized).unwrap();
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
        let serialized = bincode::serialize(&result).unwrap();
        let deserialized: RbacResult = bincode::deserialize(&serialized).unwrap();
        assert!(deserialized.allowed);
        assert!(deserialized.reason.is_none());
    }

    #[test]
    fn test_rbac_result_denied_with_reason() {
        let result = RbacResult {
            allowed: false,
            reason: Some("Insufficient permissions".to_string()),
        };
        let serialized = bincode::serialize(&result).unwrap();
        let deserialized: RbacResult = bincode::deserialize(&serialized).unwrap();
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
            let serialized = bincode::serialize(&event).unwrap();
            let _: AuditEventType = bincode::deserialize(&serialized).unwrap();
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
        
        let serialized = bincode::serialize(&msg).unwrap();
        let deserialized: Message = bincode::deserialize(&serialized).unwrap();
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
        
        let serialized = bincode::serialize(&msg).unwrap();
        let deserialized: Message = bincode::deserialize(&serialized).unwrap();
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
        let serialized = bincode::serialize(&msg).unwrap();
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
            let serialized = bincode::serialize(&msg).unwrap();
            let deserialized: Message = bincode::deserialize(&serialized).unwrap();
            // Just verify it doesn't panic
            let _ = deserialized.request_id();
        }
    }
}
