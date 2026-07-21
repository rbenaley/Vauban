/// VAUBAN Web - Session model.
///
/// Proxy sessions for SSH/RDP connections.
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::schema::proxy_sessions;

// Helper type for deserializing Inet to IpAddr
// Diesel's network-address feature provides FromSql for IpAddr with Inet
// We use deserialize_as to convert automatically

/// Session type / transport.
///
/// Three values today:
///   - `Ssh`: classical SSH session opened from a browser tab via the
///     vauban-proxy-ssh client. Recorded as asciicast.
///   - `Rdp`: classical RDP session opened from a browser tab via
///     vauban-proxy-rdp. Recorded as Vauban-RDP cast.
///   - `IacsTunnel`: TCP tunnel opened from an onboarded EWS via the
///     in-process IACS sshd (`services::iacs_tunnel`). Not recorded
///     (raw TCP forwarding, no PTY, no command parsing). Persisted on
///     `proxy_sessions` exactly the same shape, with `industrial_protocol`
///     and `ews_uuid` columns set (CHECK constraint enforces the
///     consistency at the DB layer).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    diesel::expression::AsExpression,
    diesel::deserialize::FromSqlRow,
)]
#[serde(rename_all = "snake_case")]
#[diesel(sql_type = diesel::sql_types::Varchar)]
pub enum SessionType {
    Ssh,
    Rdp,
    IacsTunnel,
}

impl SessionType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ssh => "ssh",
            Self::Rdp => "rdp",
            Self::IacsTunnel => "iacs_tunnel",
        }
    }

    /// Lossy parse: unknown values fall back to `Ssh`. Callers that
    /// need strict parsing should use `try_parse` and handle the
    /// `None` branch explicitly.
    pub fn parse(s: &str) -> Self {
        match s {
            "rdp" => Self::Rdp,
            "iacs_tunnel" => Self::IacsTunnel,
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
            "iacs_tunnel" => Some(Self::IacsTunnel),
            _ => None,
        }
    }

    /// Whether this session is an IACS tunnel.
    pub fn is_iacs_tunnel(&self) -> bool {
        matches!(self, Self::IacsTunnel)
    }

    /// Exhaustive enumeration of every variant.
    pub const ALL: &'static [SessionType] =
        &[SessionType::Ssh, SessionType::Rdp, SessionType::IacsTunnel];
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

/// Session status. The first 9 variants apply to every session type;
/// the last two (`WaitingClient`, `TunnelActive`) are introduced for
/// IACS tunnels but stay represented as plain strings on the row to
/// avoid an enum-typed schema column. `Active` from the SSH/RDP world
/// roughly corresponds to `TunnelActive` from the IACS world; we keep
/// them distinct so a viewer template can render an IACS-specific
/// state badge without ambiguity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionStatus {
    Pending,
    Approved,
    Rejected,
    /// JIT grant revoked by an approver after approval.
    Revoked,
    Expired,
    /// The parent asset was irreversibly deleted while the approval
    /// request was still pending.
    Orphaned,
    Connecting,
    Active,
    Disconnected,
    Terminated,
    Failed,
    /// IACS-only: the session was created server-side but the EWS has
    /// not yet completed the SSH handshake. Reaped after
    /// `[industrial.iacs_tunnel].waiting_client_ttl_seconds` if no EWS
    /// connects (then transitions to `Expired`).
    WaitingClient,
    /// IACS-only: the EWS SSH handshake has succeeded (key proven,
    /// authenticated presence on the bastion) but no `direct-tcpip`
    /// channel has opened yet. Reaped after the same TTL anchored on
    /// `connected_at` if the EWS stays silent.
    EwsConnected,
    /// IACS-only: the EWS handshake has succeeded and a `direct-tcpip`
    /// channel is forwarding bytes to the configured target.
    TunnelActive,
}

impl SessionStatus {
    /// Every status, i.e. the canonical closed vocabulary of the
    /// `proxy_sessions.status` column. Kept in lock-step with the
    /// `proxy_sessions_status_chk` DB constraint and the
    /// `check_status_vocabulary.sh` lint by
    /// `tests/web/status_vocab_drift_test.rs`.
    pub const ALL: &'static [Self] = &[
        Self::Pending,
        Self::Approved,
        Self::Rejected,
        Self::Revoked,
        Self::Expired,
        Self::Orphaned,
        Self::Connecting,
        Self::Active,
        Self::Disconnected,
        Self::Terminated,
        Self::Failed,
        Self::WaitingClient,
        Self::EwsConnected,
        Self::TunnelActive,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::Orphaned => "orphaned",
            Self::Connecting => "connecting",
            Self::Active => "active",
            Self::Disconnected => "disconnected",
            Self::Terminated => "terminated",
            Self::Failed => "failed",
            Self::WaitingClient => "waiting_client",
            Self::EwsConnected => "ews_connected",
            Self::TunnelActive => "tunnel_active",
        }
    }

    /// Display label. Exhaustive on purpose (no `_` arm): adding a
    /// variant without classifying its label refuses to compile.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Pending => "Pending",
            Self::Approved => "Approved",
            Self::Rejected => "Rejected",
            Self::Revoked => "Revoked",
            Self::Expired => "Expired",
            Self::Orphaned => "Orphaned",
            Self::Connecting => "Connecting",
            Self::Active => "Active",
            Self::Disconnected => "Disconnected",
            Self::Terminated => "Terminated",
            Self::Failed => "Failed",
            Self::WaitingClient => "Waiting client",
            Self::EwsConnected => "EWS connected",
            Self::TunnelActive => "Tunnel active",
        }
    }

    /// Lenient parse for DISPLAY paths only: unknown values fall back
    /// to `Pending`. Never persist through this -- use
    /// [`Self::parse_strict`] on write paths.
    pub fn parse(s: &str) -> Self {
        Self::parse_strict(s).unwrap_or(Self::Pending)
    }

    /// Strict parse for WRITE paths: `None` for anything outside the
    /// closed vocabulary (mirror of `AssetStatus::parse_strict`; the
    /// `proxy_sessions_status_chk` DB constraint is the last fence).
    pub fn parse_strict(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|v| v.as_str() == s)
    }

    /// Statuses representing a session that is "live" enough to hold
    /// resources (broadcast targets, registry entries, etc.).
    pub fn is_live(&self) -> bool {
        matches!(
            self,
            Self::Connecting
                | Self::Active
                | Self::WaitingClient
                | Self::EwsConnected
                | Self::TunnelActive
        )
    }

    /// Wire strings for [`Self::is_live`] -- resource-hold / cascade
    /// terminate / session-limit accounting.
    pub const LIVE_AS_STR: [&str; 5] = [
        "connecting",
        "active",
        "waiting_client",
        "ews_connected",
        "tunnel_active",
    ];

    /// Operator "Active Sessions" / Bastion Watch LIVE surface
    /// (connected enough to show; excludes `waiting_client` and
    /// `connecting`).
    pub const OPERATOR_ACTIVE_AS_STR: [&str; 3] = ["active", "ews_connected", "tunnel_active"];

    /// IACS open lifecycle (pending EWS, authenticated, or tunneling).
    pub const IACS_OPEN_AS_STR: [&str; 3] = ["waiting_client", "ews_connected", "tunnel_active"];

    /// IACS pre-channel TTL reap window.
    pub const WAITING_TTL_AS_STR: [&str; 2] = ["waiting_client", "ews_connected"];

    /// IACS post-auth (EWS proven; channel may or may not be open).
    pub const IACS_AUTH_AS_STR: [&str; 2] = ["ews_connected", "tunnel_active"];

    /// SSH/RDP handshake + active (WS revalidate / activity).
    pub const SSH_RDP_INFLIGHT_AS_STR: [&str; 2] = ["connecting", "active"];

    pub fn is_operator_active(&self) -> bool {
        matches!(self, Self::Active | Self::EwsConnected | Self::TunnelActive)
    }

    pub fn is_iacs_open(&self) -> bool {
        matches!(
            self,
            Self::WaitingClient | Self::EwsConnected | Self::TunnelActive
        )
    }

    pub fn is_waiting_ttl(&self) -> bool {
        matches!(self, Self::WaitingClient | Self::EwsConnected)
    }

    pub fn is_iacs_authenticated(&self) -> bool {
        matches!(self, Self::EwsConnected | Self::TunnelActive)
    }

    pub fn is_ssh_rdp_inflight(&self) -> bool {
        matches!(self, Self::Connecting | Self::Active)
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
    pub approved_by_id: Option<i32>,
    pub approved_at: Option<DateTime<Utc>>,
    pub max_session_duration: Option<i32>,
    pub expires_at: Option<DateTime<Utc>>,
    pub rejected_by_id: Option<i32>,
    pub rejected_at: Option<DateTime<Utc>>,
    pub decision_reason: Option<String>,
    // Recording integrity bundle, populated by recording_hydrator after
    // session disconnect. NULL while the hydrator has not yet processed
    // the row (typical window: a few seconds; up to one tick interval).
    pub recording_blake3: Option<String>,
    pub recording_size_bytes: Option<i64>,
    pub recording_duration_ms: Option<i64>,
    pub recording_event_count: Option<i32>,
    pub recording_format: Option<String>,
    pub recording_width: Option<i16>,
    pub recording_height: Option<i16>,
    pub recording_segment_count: Option<i32>,
    pub recording_codec: Option<String>,
    pub recording_finalized_at: Option<DateTime<Utc>>,
    /// IACS-specific. NULL for SSH / RDP rows; pinned by the SQL CHECK
    /// constraint `proxy_sessions_iacs_consistency`.
    pub industrial_protocol: Option<String>,
    /// IACS-specific. NULL for SSH / RDP rows. References `ews.uuid`
    /// (`ON DELETE SET NULL` so an offboard hard-delete preserves the
    /// audit row).
    pub ews_uuid: Option<Uuid>,
    /// IACS-specific. The actual address the in-process IACS proxy
    /// connected to; today always `127.0.0.1:4321` (config), tomorrow
    /// derived from `asset.hostname:asset.port` once bastion->asset
    /// routing lands.
    pub tunnel_target_addr: Option<String>,
    /// Set when an APPROVED JIT grant was revoked by an admin
    /// (`status = 'revoked'`). References `users.id` (`ON DELETE SET
    /// NULL`).
    pub revoked_by_id: Option<i32>,
    /// Timestamp of the revocation decision.
    pub revoked_at: Option<DateTime<Utc>>,
    /// Sticky latch: SSH/RDP audit `try_send` dropped >=1 frame.
    /// Always false for IACS (ack-block). Set by web on
    /// `Message::RecordingLossObserved`.
    ///
    /// Column order must match `schema::proxy_sessions` (appended after
    /// `revoked_at` by migration `20260722000000_recording_lossy_flag`).
    pub recording_lossy: bool,
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
    pub max_session_duration: Option<i32>,
    /// IACS-only. Must be `Some(_)` when `session_type =
    /// SessionType::IacsTunnel`, otherwise `None` (DB CHECK).
    pub industrial_protocol: Option<String>,
    /// IACS-only. Must be `Some(_)` when `session_type =
    /// SessionType::IacsTunnel`, otherwise `None` (DB CHECK).
    pub ews_uuid: Option<Uuid>,
    /// IACS-only. May be `None` while in `waiting_client`; filled on
    /// transition to `tunnel_active`.
    pub tunnel_target_addr: Option<String>,
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
            approved_by_id: None,
            approved_at: None,
            max_session_duration: None,
            expires_at: None,
            rejected_by_id: None,
            rejected_at: None,
            decision_reason: None,
            recording_blake3: None,
            recording_size_bytes: None,
            recording_duration_ms: None,
            recording_event_count: None,
            recording_format: None,
            recording_width: None,
            recording_height: None,
            recording_segment_count: None,
            recording_codec: None,
            recording_finalized_at: None,
            industrial_protocol: None,
            ews_uuid: None,
            tunnel_target_addr: None,
            revoked_by_id: None,
            revoked_at: None,
            recording_lossy: false,
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
    fn test_session_type_from_str_iacs_tunnel() {
        assert_eq!(SessionType::parse("iacs_tunnel"), SessionType::IacsTunnel);
        assert_eq!(
            SessionType::try_parse("iacs_tunnel"),
            Some(SessionType::IacsTunnel)
        );
        assert_eq!(SessionType::IacsTunnel.as_str(), "iacs_tunnel");
        assert!(SessionType::IacsTunnel.is_iacs_tunnel());
        assert!(!SessionType::Ssh.is_iacs_tunnel());
        assert!(!SessionType::Rdp.is_iacs_tunnel());
    }

    #[test]
    fn test_session_type_all_is_exhaustive() {
        for variant in SessionType::ALL {
            match *variant {
                SessionType::Ssh | SessionType::Rdp | SessionType::IacsTunnel => {}
            }
        }
        assert_eq!(SessionType::ALL.len(), 3);
    }

    #[test]
    fn test_session_status_iacs_variants() {
        assert_eq!(
            SessionStatus::parse("waiting_client"),
            SessionStatus::WaitingClient
        );
        assert_eq!(
            SessionStatus::parse("ews_connected"),
            SessionStatus::EwsConnected
        );
        assert_eq!(
            SessionStatus::parse("tunnel_active"),
            SessionStatus::TunnelActive
        );
        assert_eq!(SessionStatus::WaitingClient.as_str(), "waiting_client");
        assert_eq!(SessionStatus::EwsConnected.as_str(), "ews_connected");
        assert_eq!(SessionStatus::TunnelActive.as_str(), "tunnel_active");
        assert!(SessionStatus::WaitingClient.is_live());
        assert!(SessionStatus::EwsConnected.is_live());
        assert!(SessionStatus::TunnelActive.is_live());
        assert!(!SessionStatus::Terminated.is_live());
        assert!(SessionStatus::Active.is_live());
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
    }

    #[test]
    fn test_session_type_roundtrip() {
        for session_type in [SessionType::Ssh, SessionType::Rdp] {
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
    fn test_session_status_from_str_approved() {
        assert_eq!(SessionStatus::parse("approved"), SessionStatus::Approved);
    }

    #[test]
    fn test_session_status_from_str_rejected() {
        assert_eq!(SessionStatus::parse("rejected"), SessionStatus::Rejected);
    }

    #[test]
    fn test_session_status_from_str_expired() {
        assert_eq!(SessionStatus::parse("expired"), SessionStatus::Expired);
    }

    #[test]
    fn test_session_status_from_str_unknown() {
        assert_eq!(SessionStatus::parse("unknown"), SessionStatus::Pending);
        assert_eq!(SessionStatus::parse(""), SessionStatus::Pending);
    }

    #[test]
    fn test_session_status_as_str() {
        assert_eq!(SessionStatus::Pending.as_str(), "pending");
        assert_eq!(SessionStatus::Approved.as_str(), "approved");
        assert_eq!(SessionStatus::Rejected.as_str(), "rejected");
        assert_eq!(SessionStatus::Expired.as_str(), "expired");
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
            SessionStatus::Approved,
            SessionStatus::Rejected,
            SessionStatus::Expired,
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
        assert!((3590..=3610).contains(&dur));
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
        assert!((3590..=3610).contains(&duration));
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
        let cloned = session_type;
        assert_eq!(session_type, cloned);
    }

    #[test]
    fn test_session_type_copy() {
        let session_type = SessionType::Rdp;
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
        let cloned = status;
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
    fn test_status_enum_all_values() {
        let statuses = [
            ("pending", SessionStatus::Pending),
            ("approved", SessionStatus::Approved),
            ("rejected", SessionStatus::Rejected),
            ("expired", SessionStatus::Expired),
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
            max_session_duration: None,
            industrial_protocol: None,
            ews_uuid: None,
            tunnel_target_addr: None,
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
            max_session_duration: Some(3600),
            industrial_protocol: None,
            ews_uuid: None,
            tunnel_target_addr: None,
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
            session_type: SessionType::Rdp,
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
