/// VAUBAN Web - Session model.
///
/// Proxy sessions for SSH/RDP/VNC connections.

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel::sql_types::Inet;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
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
    pub client_ip: String,
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
    pub client_ip: String,
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

