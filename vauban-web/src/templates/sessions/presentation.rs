//! Pure presentation rules for session and JIT grant rows.
//!
//! A JIT grant and the SSH/RDP session created from it are two different
//! `proxy_sessions` rows. Grant rows use an internal credential sentinel
//! because the schema predates JIT and keeps the credential columns NOT NULL.
//! The sentinel must never cross the HTML/JSON presentation boundary.

use chrono::{DateTime, Utc};

pub const PENDING_CREDENTIAL_ID: &str = "pending";

#[derive(Debug, Clone, Copy)]
pub struct SessionPresentationInput<'a> {
    pub credential_id: &'a str,
    pub credential_username: &'a str,
    pub requester_username: &'a str,
    pub session_type: &'a str,
    pub tunnel_target_addr: Option<&'a str>,
    pub status: &'a str,
    pub created_at: DateTime<Utc>,
    pub connected_at: Option<DateTime<Utc>>,
    pub disconnected_at: Option<DateTime<Utc>>,
    pub recording_path: Option<&'a str>,
    pub is_recorded: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisplayIdentity {
    Credential(String),
    Requester(String),
    TunnelTarget(String),
    Unavailable,
}

impl DisplayIdentity {
    pub fn value(&self) -> &str {
        match self {
            Self::Credential(value) | Self::Requester(value) | Self::TunnelTarget(value) => value,
            Self::Unavailable => "-",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Requester(_) => "Requested by",
            Self::Credential(_) | Self::TunnelTarget(_) | Self::Unavailable => "",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimelineEvent {
    Connected(DateTime<Utc>),
    Requested(DateTime<Utc>),
}

impl TimelineEvent {
    pub fn label(self) -> &'static str {
        match self {
            Self::Connected(_) => "Connected",
            Self::Requested(_) => "Requested",
        }
    }

    pub fn at(self) -> DateTime<Utc> {
        match self {
            Self::Connected(at) | Self::Requested(at) => at,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordingState {
    NotRecorded,
    Enabled,
    Recorded,
}

pub fn is_jit_grant(credential_id: &str) -> bool {
    credential_id == PENDING_CREDENTIAL_ID
}

pub fn display_identity(input: &SessionPresentationInput<'_>) -> DisplayIdentity {
    if is_jit_grant(input.credential_id) {
        let requester = input.requester_username.trim();
        return if requester.is_empty() {
            DisplayIdentity::Unavailable
        } else {
            DisplayIdentity::Requester(requester.to_string())
        };
    }

    let credential = input.credential_username.trim();
    if !credential.is_empty() {
        return DisplayIdentity::Credential(credential.to_string());
    }

    if input.session_type == "iacs_tunnel"
        && let Some(target) = input.tunnel_target_addr.map(str::trim)
        && !target.is_empty()
    {
        return DisplayIdentity::TunnelTarget(target.to_string());
    }

    DisplayIdentity::Unavailable
}

pub fn credential_label(input: &SessionPresentationInput<'_>) -> String {
    if is_jit_grant(input.credential_id) {
        "Not selected (request never connected)".to_string()
    } else if input.session_type == "iacs_tunnel" && input.credential_username.trim().is_empty() {
        "Not authenticated (IACS tunnel)".to_string()
    } else {
        let value = input.credential_username.trim();
        if value.is_empty() {
            "Unavailable".to_string()
        } else {
            value.to_string()
        }
    }
}

pub fn timeline_event(input: &SessionPresentationInput<'_>) -> TimelineEvent {
    input
        .connected_at
        .map(TimelineEvent::Connected)
        .unwrap_or(TimelineEvent::Requested(input.created_at))
}

pub fn duration_seconds(input: &SessionPresentationInput<'_>, now: DateTime<Utc>) -> Option<i64> {
    match (input.connected_at, input.disconnected_at) {
        (Some(start), Some(end)) => Some(end.signed_duration_since(start).num_seconds()),
        (Some(start), None) if input.status == "active" || input.status == "tunnel_active" => {
            Some(now.signed_duration_since(start).num_seconds())
        }
        _ => None,
    }
}

pub fn recording_state(input: &SessionPresentationInput<'_>) -> RecordingState {
    if input.connected_at.is_none() {
        RecordingState::NotRecorded
    } else if input
        .recording_path
        .is_some_and(|path| !path.trim().is_empty())
    {
        RecordingState::Recorded
    } else if input.is_recorded {
        RecordingState::Enabled
    } else {
        RecordingState::NotRecorded
    }
}
