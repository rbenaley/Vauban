//! Shared projection from session-history database rows to UI payloads.
//!
//! The HTTP page, WebSocket initial snapshot and periodic broadcaster all
//! consume this mapper so identity/timestamp semantics cannot drift.

use chrono::{DateTime, Utc};

use crate::models::session::SessionType;
use crate::templates::sessions::session_list::SessionListItem;

pub type SessionHistoryDbRow = (
    i32,
    uuid::Uuid,
    String,
    String,
    SessionType,
    String,
    String,
    String,
    Option<String>,
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
    bool,
    Option<String>,
    String,
    DateTime<Utc>,
);

#[derive(Debug)]
pub struct SessionHistoryRow {
    pub id: i32,
    pub uuid: uuid::Uuid,
    pub asset_name: String,
    pub asset_hostname: String,
    pub session_type: SessionType,
    pub status: String,
    pub credential_id: String,
    pub credential_username: String,
    pub tunnel_target_addr: Option<String>,
    pub connected_at: Option<DateTime<Utc>>,
    pub disconnected_at: Option<DateTime<Utc>>,
    pub is_recorded: bool,
    pub recording_path: Option<String>,
    pub requester_username: String,
    pub created_at: DateTime<Utc>,
}

impl From<SessionHistoryDbRow> for SessionHistoryRow {
    fn from(row: SessionHistoryDbRow) -> Self {
        let (
            id,
            uuid,
            asset_name,
            asset_hostname,
            session_type,
            status,
            credential_id,
            credential_username,
            tunnel_target_addr,
            connected_at,
            disconnected_at,
            is_recorded,
            recording_path,
            requester_username,
            created_at,
        ) = row;
        Self {
            id,
            uuid,
            asset_name,
            asset_hostname,
            session_type,
            status,
            credential_id,
            credential_username,
            tunnel_target_addr,
            connected_at,
            disconnected_at,
            is_recorded,
            recording_path,
            requester_username,
            created_at,
        }
    }
}

impl SessionHistoryRow {
    pub fn into_list_item(self, now: DateTime<Utc>) -> SessionListItem {
        let session_type = self.session_type.to_string();
        let input = crate::templates::sessions::presentation::SessionPresentationInput {
            credential_id: &self.credential_id,
            credential_username: &self.credential_username,
            requester_username: &self.requester_username,
            session_type: &session_type,
            tunnel_target_addr: self.tunnel_target_addr.as_deref(),
            status: &self.status,
            created_at: self.created_at,
            connected_at: self.connected_at,
            disconnected_at: self.disconnected_at,
            recording_path: self.recording_path.as_deref(),
            is_recorded: self.is_recorded,
        };
        let event = crate::templates::sessions::presentation::timeline_event(&input);
        let duration_seconds =
            crate::templates::sessions::presentation::duration_seconds(&input, now);

        SessionListItem {
            id: self.id,
            uuid: self.uuid.to_string(),
            asset_name: self.asset_name,
            asset_hostname: self.asset_hostname,
            session_type,
            status: self.status,
            credential_id: self.credential_id,
            credential_username: self.credential_username,
            requester_username: self.requester_username,
            tunnel_target_addr: self.tunnel_target_addr,
            connected_at: self.connected_at,
            disconnected_at: self.disconnected_at,
            created_at: self.created_at,
            event_at: event.at(),
            event_label: event.label().to_string(),
            duration_seconds,
            is_recorded: self.is_recorded,
            recording_path: self.recording_path,
        }
    }
}
