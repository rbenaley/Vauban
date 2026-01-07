/// VAUBAN Web - Session model.
///
/// Proxy sessions for SSH/RDP/VNC connections.
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::schema::proxy_sessions;

// Helper type for deserializing Inet to IpAddr
// Diesel's network-address feature provides FromSql for IpAddr with Inet
// We use deserialize_as to convert automatically

/// Session type (protocol).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionType {
    Ssh,
    Rdp,
    Vnc,
}

impl SessionType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ssh => "ssh",
            Self::Rdp => "rdp",
            Self::Vnc => "vnc",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "rdp" => Self::Rdp,
            "vnc" => Self::Vnc,
            _ => Self::Ssh,
        }
    }
}

/// Session status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionStatus {
    Pending,
    Connecting,
    Active,
    Disconnected,
    Terminated,
    Failed,
}

impl SessionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Connecting => "connecting",
            Self::Active => "active",
            Self::Disconnected => "disconnected",
            Self::Terminated => "terminated",
            Self::Failed => "failed",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "connecting" => Self::Connecting,
            "active" => Self::Active,
            "disconnected" => Self::Disconnected,
            "terminated" => Self::Terminated,
            "failed" => Self::Failed,
            _ => Self::Pending,
        }
    }
}

/// Proxy session database model.
#[derive(Debug, Clone, Queryable, Selectable, Identifiable, Associations, Serialize)]
#[diesel(table_name = proxy_sessions)]
#[diesel(belongs_to(crate::models::user::User, foreign_key = user_id))]
#[diesel(belongs_to(crate::models::asset::Asset, foreign_key = asset_id))]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct ProxySession {
    pub id: i32,
    pub uuid: Uuid,
    pub user_id: i32,
    pub asset_id: i32,
    pub credential_id: String,
    pub credential_username: String,
    pub session_type: String,
    pub status: String,
    #[serde(skip_serializing)]
    pub client_ip: IpNetwork,
    pub client_user_agent: Option<String>,
    pub proxy_instance: Option<String>,
    pub connected_at: Option<DateTime<Utc>>,
    pub disconnected_at: Option<DateTime<Utc>>,
    pub justification: Option<String>,
    pub is_recorded: bool,
    pub recording_path: Option<String>,
    pub bytes_sent: i64,
    pub bytes_received: i64,
    pub commands_count: i32,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// New session for insertion.
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = proxy_sessions)]
pub struct NewProxySession {
    pub uuid: Uuid,
    pub user_id: i32,
    pub asset_id: i32,
    pub credential_id: String,
    pub credential_username: String,
    pub session_type: String,
    pub status: String,
    pub client_ip: IpNetwork,
    pub client_user_agent: Option<String>,
    pub proxy_instance: Option<String>,
    pub justification: Option<String>,
    pub is_recorded: bool,
    pub metadata: serde_json::Value,
}

impl ProxySession {
    /// Get session type enum.
    pub fn session_type_enum(&self) -> SessionType {
        SessionType::from_str(&self.session_type)
    }

    /// Get status enum.
    pub fn status_enum(&self) -> SessionStatus {
        SessionStatus::from_str(&self.status)
    }

    /// Check if session is active.
    pub fn is_active(&self) -> bool {
        self.status_enum() == SessionStatus::Active
    }

    /// Calculate session duration in seconds.
    pub fn duration(&self) -> Option<i64> {
        if let Some(connected_at) = self.connected_at {
            let end_time = self.disconnected_at.unwrap_or_else(Utc::now);
            Some((end_time - connected_at).num_seconds())
        } else {
            None
        }
    }
}

/// Session creation request.
#[derive(Debug, Clone, Deserialize, validator::Validate)]
pub struct CreateSessionRequest {
    pub asset_id: Uuid,
    pub credential_id: String,
    pub session_type: String,
    pub justification: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    /// Helper to create a test session
    fn create_test_session() -> ProxySession {
        ProxySession {
            id: 1,
            uuid: Uuid::new_v4(),
            user_id: 1,
            asset_id: 1,
            credential_id: "cred-123".to_string(),
            credential_username: "admin".to_string(),
            session_type: "ssh".to_string(),
            status: "active".to_string(),
            client_ip: "192.168.1.10/32".parse().unwrap(),
            client_user_agent: Some("Mozilla/5.0".to_string()),
            proxy_instance: Some("proxy-01".to_string()),
            connected_at: Some(Utc::now() - Duration::hours(1)),
            disconnected_at: None,
            justification: Some("Maintenance task".to_string()),
            is_recorded: true,
            recording_path: Some("/recordings/session-1.cast".to_string()),
            bytes_sent: 1024,
            bytes_received: 2048,
            commands_count: 15,
            metadata: serde_json::json!({}),
            created_at: Utc::now() - Duration::hours(1),
            updated_at: Utc::now(),
        }
    }

    // ==================== SessionType Tests ====================

    #[test]
    fn test_session_type_from_str_ssh() {
        assert_eq!(SessionType::from_str("ssh"), SessionType::Ssh);
    }

    #[test]
    fn test_session_type_from_str_rdp() {
        assert_eq!(SessionType::from_str("rdp"), SessionType::Rdp);
    }

    #[test]
    fn test_session_type_from_str_vnc() {
        assert_eq!(SessionType::from_str("vnc"), SessionType::Vnc);
    }

    #[test]
    fn test_session_type_from_str_unknown() {
        assert_eq!(SessionType::from_str("unknown"), SessionType::Ssh);
        assert_eq!(SessionType::from_str(""), SessionType::Ssh);
    }

    #[test]
    fn test_session_type_as_str() {
        assert_eq!(SessionType::Ssh.as_str(), "ssh");
        assert_eq!(SessionType::Rdp.as_str(), "rdp");
        assert_eq!(SessionType::Vnc.as_str(), "vnc");
    }

    #[test]
    fn test_session_type_roundtrip() {
        for session_type in [SessionType::Ssh, SessionType::Rdp, SessionType::Vnc] {
            let str_val = session_type.as_str();
            let parsed = SessionType::from_str(str_val);
            assert_eq!(session_type, parsed);
        }
    }

    // ==================== SessionStatus Tests ====================

    #[test]
    fn test_session_status_from_str_pending() {
        assert_eq!(SessionStatus::from_str("pending"), SessionStatus::Pending);
    }

    #[test]
    fn test_session_status_from_str_connecting() {
        assert_eq!(
            SessionStatus::from_str("connecting"),
            SessionStatus::Connecting
        );
    }

    #[test]
    fn test_session_status_from_str_active() {
        assert_eq!(SessionStatus::from_str("active"), SessionStatus::Active);
    }

    #[test]
    fn test_session_status_from_str_disconnected() {
        assert_eq!(
            SessionStatus::from_str("disconnected"),
            SessionStatus::Disconnected
        );
    }

    #[test]
    fn test_session_status_from_str_terminated() {
        assert_eq!(
            SessionStatus::from_str("terminated"),
            SessionStatus::Terminated
        );
    }

    #[test]
    fn test_session_status_from_str_failed() {
        assert_eq!(SessionStatus::from_str("failed"), SessionStatus::Failed);
    }

    #[test]
    fn test_session_status_from_str_unknown() {
        assert_eq!(SessionStatus::from_str("unknown"), SessionStatus::Pending);
        assert_eq!(SessionStatus::from_str(""), SessionStatus::Pending);
    }

    #[test]
    fn test_session_status_as_str() {
        assert_eq!(SessionStatus::Pending.as_str(), "pending");
        assert_eq!(SessionStatus::Connecting.as_str(), "connecting");
        assert_eq!(SessionStatus::Active.as_str(), "active");
        assert_eq!(SessionStatus::Disconnected.as_str(), "disconnected");
        assert_eq!(SessionStatus::Terminated.as_str(), "terminated");
        assert_eq!(SessionStatus::Failed.as_str(), "failed");
    }

    #[test]
    fn test_session_status_roundtrip() {
        for status in [
            SessionStatus::Pending,
            SessionStatus::Connecting,
            SessionStatus::Active,
            SessionStatus::Disconnected,
            SessionStatus::Terminated,
            SessionStatus::Failed,
        ] {
            let str_val = status.as_str();
            let parsed = SessionStatus::from_str(str_val);
            assert_eq!(status, parsed);
        }
    }

    // ==================== ProxySession Method Tests ====================

    #[test]
    fn test_session_type_enum() {
        let session = create_test_session();
        assert_eq!(session.session_type_enum(), SessionType::Ssh);
    }

    #[test]
    fn test_session_status_enum() {
        let session = create_test_session();
        assert_eq!(session.status_enum(), SessionStatus::Active);
    }

    #[test]
    fn test_is_active_when_active() {
        let session = create_test_session();
        assert!(session.is_active());
    }

    #[test]
    fn test_is_active_when_not_active() {
        let mut session = create_test_session();
        session.status = "disconnected".to_string();
        assert!(!session.is_active());
    }

    #[test]
    fn test_is_active_when_pending() {
        let mut session = create_test_session();
        session.status = "pending".to_string();
        assert!(!session.is_active());
    }

    // ==================== Duration Tests ====================

    #[test]
    fn test_duration_with_connected_at() {
        let session = create_test_session();
        let duration = session.duration();

        assert!(duration.is_some());
        // Duration should be approximately 1 hour (3600 seconds), give or take
        let dur = duration.unwrap();
        assert!(dur >= 3590 && dur <= 3610);
    }

    #[test]
    fn test_duration_without_connected_at() {
        let mut session = create_test_session();
        session.connected_at = None;

        assert!(session.duration().is_none());
    }

    #[test]
    fn test_duration_with_disconnected_at() {
        let mut session = create_test_session();
        let connect_time = Utc::now() - Duration::hours(2);
        let disconnect_time = Utc::now() - Duration::hours(1);

        session.connected_at = Some(connect_time);
        session.disconnected_at = Some(disconnect_time);

        let duration = session.duration().unwrap();
        // Should be approximately 1 hour (3600 seconds)
        assert!(duration >= 3590 && duration <= 3610);
    }
}
