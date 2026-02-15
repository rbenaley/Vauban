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

/// Session type (protocol) (L-7: Diesel enum instead of String).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize,
    diesel::expression::AsExpression, diesel::deserialize::FromSqlRow,
)]
#[serde(rename_all = "lowercase")]
#[diesel(sql_type = diesel::sql_types::Varchar)]
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

    pub fn parse(s: &str) -> Self {
        match s {
            "rdp" => Self::Rdp,
            "vnc" => Self::Vnc,
            _ => Self::Ssh,
        }
    }

    /// Try to parse a string into a SessionType, returning None for unknown values.
    /// Use this for user-supplied filter parameters where an invalid value should
    /// match nothing rather than silently default to SSH.
    pub fn try_parse(s: &str) -> Option<Self> {
        match s {
            "ssh" => Some(Self::Ssh),
            "rdp" => Some(Self::Rdp),
            "vnc" => Some(Self::Vnc),
            _ => None,
        }
    }
}

impl std::fmt::Display for SessionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl diesel::serialize::ToSql<diesel::sql_types::Varchar, diesel::pg::Pg> for SessionType {
    fn to_sql<'b>(
        &'b self,
        out: &mut diesel::serialize::Output<'b, '_, diesel::pg::Pg>,
    ) -> diesel::serialize::Result {
        <str as diesel::serialize::ToSql<diesel::sql_types::Varchar, diesel::pg::Pg>>::to_sql(
            self.as_str(),
            out,
        )
    }
}

impl diesel::deserialize::FromSql<diesel::sql_types::Varchar, diesel::pg::Pg> for SessionType {
    fn from_sql(
        bytes: <diesel::pg::Pg as diesel::backend::Backend>::RawValue<'_>,
    ) -> diesel::deserialize::Result<Self> {
        let s = <String as diesel::deserialize::FromSql<
            diesel::sql_types::Varchar,
            diesel::pg::Pg,
        >>::from_sql(bytes)?;
        Ok(Self::parse(&s))
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

    pub fn parse(s: &str) -> Self {
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
    pub session_type: SessionType,
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
    pub session_type: SessionType,
    pub status: String,
    pub client_ip: IpNetwork,
    pub client_user_agent: Option<String>,
    pub proxy_instance: Option<String>,
    pub justification: Option<String>,
    pub is_recorded: bool,
    pub metadata: serde_json::Value,
}

impl ProxySession {
    /// Get status enum.
    pub fn status_enum(&self) -> SessionStatus {
        SessionStatus::parse(&self.status)
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
    pub session_type: SessionType,
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
            session_type: SessionType::Ssh,
            status: "active".to_string(),
            client_ip: unwrap_ok!("192.168.1.10/32".parse()),
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
        assert_eq!(SessionType::parse("ssh"), SessionType::Ssh);
    }

    #[test]
    fn test_session_type_from_str_rdp() {
        assert_eq!(SessionType::parse("rdp"), SessionType::Rdp);
    }

    #[test]
    fn test_session_type_from_str_vnc() {
        assert_eq!(SessionType::parse("vnc"), SessionType::Vnc);
    }

    #[test]
    fn test_session_type_from_str_unknown() {
        assert_eq!(SessionType::parse("unknown"), SessionType::Ssh);
        assert_eq!(SessionType::parse(""), SessionType::Ssh);
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
            let parsed = SessionType::parse(str_val);
            assert_eq!(session_type, parsed);
        }
    }

    // ==================== SessionStatus Tests ====================

    #[test]
    fn test_session_status_from_str_pending() {
        assert_eq!(SessionStatus::parse("pending"), SessionStatus::Pending);
    }

    #[test]
    fn test_session_status_from_str_connecting() {
        assert_eq!(
            SessionStatus::parse("connecting"),
            SessionStatus::Connecting
        );
    }

    #[test]
    fn test_session_status_from_str_active() {
        assert_eq!(SessionStatus::parse("active"), SessionStatus::Active);
    }

    #[test]
    fn test_session_status_from_str_disconnected() {
        assert_eq!(
            SessionStatus::parse("disconnected"),
            SessionStatus::Disconnected
        );
    }

    #[test]
    fn test_session_status_from_str_terminated() {
        assert_eq!(
            SessionStatus::parse("terminated"),
            SessionStatus::Terminated
        );
    }

    #[test]
    fn test_session_status_from_str_failed() {
        assert_eq!(SessionStatus::parse("failed"), SessionStatus::Failed);
    }

    #[test]
    fn test_session_status_from_str_unknown() {
        assert_eq!(SessionStatus::parse("unknown"), SessionStatus::Pending);
        assert_eq!(SessionStatus::parse(""), SessionStatus::Pending);
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
            let parsed = SessionStatus::parse(str_val);
            assert_eq!(status, parsed);
        }
    }

    // ==================== ProxySession Method Tests ====================

    #[test]
    fn test_session_type_field_is_enum() {
        let session = create_test_session();
        assert_eq!(session.session_type, SessionType::Ssh);
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
        let dur = unwrap_some!(duration);
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

        let duration = unwrap_some!(session.duration());
        // Should be approximately 1 hour (3600 seconds)
        assert!(duration >= 3590 && duration <= 3610);
    }

    // ==================== SessionType Additional Tests ====================

    #[test]
    fn test_session_type_debug() {
        let session_type = SessionType::Ssh;
        let debug_str = format!("{:?}", session_type);
        assert!(debug_str.contains("Ssh"));
    }

    #[test]
    fn test_session_type_clone() {
        let session_type = SessionType::Rdp;
        let cloned = session_type.clone();
        assert_eq!(session_type, cloned);
    }

    #[test]
    fn test_session_type_copy() {
        let session_type = SessionType::Vnc;
        let copied = session_type;
        assert_eq!(session_type, copied);
    }

    #[test]
    fn test_session_type_serialize() {
        let session_type = SessionType::Ssh;
        let json = unwrap_ok!(serde_json::to_string(&session_type));
        assert!(json.contains("ssh"));
    }

    #[test]
    fn test_session_type_deserialize() {
        let json = r#""rdp""#;
        let session_type: SessionType = unwrap_ok!(serde_json::from_str(json));
        assert_eq!(session_type, SessionType::Rdp);
    }

    #[test]
    fn test_session_type_display() {
        assert_eq!(SessionType::Ssh.to_string(), "ssh");
        assert_eq!(SessionType::Rdp.to_string(), "rdp");
        assert_eq!(SessionType::Vnc.to_string(), "vnc");
    }

    // ==================== SessionStatus Additional Tests ====================

    #[test]
    fn test_session_status_debug() {
        let status = SessionStatus::Active;
        let debug_str = format!("{:?}", status);
        assert!(debug_str.contains("Active"));
    }

    #[test]
    fn test_session_status_clone() {
        let status = SessionStatus::Pending;
        let cloned = status.clone();
        assert_eq!(status, cloned);
    }

    #[test]
    fn test_session_status_copy() {
        let status = SessionStatus::Failed;
        let copied = status;
        assert_eq!(status, copied);
    }

    #[test]
    fn test_session_status_serialize() {
        let status = SessionStatus::Terminated;
        let json = unwrap_ok!(serde_json::to_string(&status));
        assert!(json.contains("Terminated"));
    }

    // ==================== ProxySession Additional Tests ====================

    #[test]
    fn test_proxy_session_clone() {
        let session = create_test_session();
        let cloned = session.clone();
        assert_eq!(session.uuid, cloned.uuid);
        assert_eq!(session.status, cloned.status);
    }

    #[test]
    fn test_proxy_session_debug() {
        let session = create_test_session();
        let debug_str = format!("{:?}", session);
        assert!(debug_str.contains("ProxySession"));
    }

    #[test]
    fn test_proxy_session_serialize() {
        let session = create_test_session();
        let json = unwrap_ok!(serde_json::to_string(&session));
        assert!(json.contains("active"));
        // client_ip should be skipped
        assert!(!json.contains("192.168.1.10"));
    }

    #[test]
    fn test_session_type_field_rdp() {
        let mut session = create_test_session();
        session.session_type = SessionType::Rdp;
        assert_eq!(session.session_type, SessionType::Rdp);
    }

    #[test]
    fn test_session_type_field_vnc() {
        let mut session = create_test_session();
        session.session_type = SessionType::Vnc;
        assert_eq!(session.session_type, SessionType::Vnc);
    }

    #[test]
    fn test_status_enum_all_values() {
        let statuses = [
            ("pending", SessionStatus::Pending),
            ("connecting", SessionStatus::Connecting),
            ("active", SessionStatus::Active),
            ("disconnected", SessionStatus::Disconnected),
            ("terminated", SessionStatus::Terminated),
            ("failed", SessionStatus::Failed),
        ];

        for (status_str, expected) in statuses {
            let mut session = create_test_session();
            session.status = status_str.to_string();
            assert_eq!(session.status_enum(), expected);
        }
    }

    // ==================== NewProxySession Tests ====================

    #[test]
    fn test_new_proxy_session_debug() {
        let new_session = NewProxySession {
            uuid: Uuid::new_v4(),
            user_id: 1,
            asset_id: 1,
            credential_id: "cred-1".to_string(),
            credential_username: "admin".to_string(),
            session_type: SessionType::Ssh,
            status: "pending".to_string(),
            client_ip: unwrap_ok!("10.0.0.1".parse()),
            client_user_agent: Some("Mozilla/5.0".to_string()),
            proxy_instance: None,
            justification: Some("Maintenance".to_string()),
            is_recorded: true,
            metadata: serde_json::json!({}),
        };

        let debug_str = format!("{:?}", new_session);
        assert!(debug_str.contains("NewProxySession"));
    }

    #[test]
    fn test_new_proxy_session_clone() {
        let new_session = NewProxySession {
            uuid: Uuid::new_v4(),
            user_id: 2,
            asset_id: 3,
            credential_id: "cred-2".to_string(),
            credential_username: "root".to_string(),
            session_type: SessionType::Rdp,
            status: "connecting".to_string(),
            client_ip: unwrap_ok!("192.168.1.1".parse()),
            client_user_agent: None,
            proxy_instance: Some("proxy-02".to_string()),
            justification: None,
            is_recorded: false,
            metadata: serde_json::json!({"key": "value"}),
        };

        let cloned = new_session.clone();
        assert_eq!(new_session.credential_id, cloned.credential_id);
    }

    // ==================== CreateSessionRequest Tests ====================

    #[test]
    fn test_create_session_request_debug() {
        let request = CreateSessionRequest {
            asset_id: Uuid::new_v4(),
            credential_id: "cred-debug".to_string(),
            session_type: SessionType::Ssh,
            justification: Some("Debug session".to_string()),
        };

        let debug_str = format!("{:?}", request);
        assert!(debug_str.contains("CreateSessionRequest"));
    }

    #[test]
    fn test_create_session_request_clone() {
        let request = CreateSessionRequest {
            asset_id: Uuid::new_v4(),
            credential_id: "cred-clone".to_string(),
            session_type: SessionType::Vnc,
            justification: None,
        };

        let cloned = request.clone();
        assert_eq!(request.credential_id, cloned.credential_id);
    }

    #[test]
    fn test_create_session_request_validation_valid() {
        use validator::Validate;

        let request = CreateSessionRequest {
            asset_id: Uuid::new_v4(),
            credential_id: "cred-valid".to_string(),
            session_type: SessionType::Ssh,
            justification: Some("Valid request".to_string()),
        };

        assert!(request.validate().is_ok());
    }

    // ==================== Duration Edge Cases ====================

    #[test]
    fn test_duration_zero_seconds() {
        let mut session = create_test_session();
        let now = Utc::now();
        session.connected_at = Some(now);
        session.disconnected_at = Some(now);

        let duration = unwrap_some!(session.duration());
        assert_eq!(duration, 0);
    }

    #[test]
    fn test_duration_negative_handled() {
        let mut session = create_test_session();
        // This would be an invalid state, but test it anyway
        session.connected_at = Some(Utc::now());
        session.disconnected_at = Some(Utc::now() - Duration::hours(1));

        let duration = unwrap_some!(session.duration());
        // Duration would be negative
        assert!(duration < 0);
    }
}
