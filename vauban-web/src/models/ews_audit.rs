//! Append-only audit trail for IACS / EWS lifecycle events.
//!
//! Mirrors the JIT `approval_audit_log` pattern. Every state transition
//! (submit, edit, cancel, approve, reject, disable, enable, offboard)
//! writes one row. The `block_ews_audit_log_mutation` PostgreSQL trigger
//! rejects every UPDATE / DELETE except the FK-cascaded SET NULL on the
//! actor / target user-id columns; the snapshot usernames and every
//! audit-significant field stay immutable.
//!
//! Inserts are performed inside the same Diesel transaction as the
//! state mutation that triggers them (in `vauban-access`), so the trail
//! is atomically consistent with the business decision: any sub-step
//! failure rolls back the whole thing -- never a half-state.

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::schema::ews_audit_log;

/// One of the eight audit events. Mirrors the DB-level CHECK constraint
/// `ews_audit_log_event_check`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EwsAuditEvent {
    Submitted,
    Edited,
    Cancelled,
    Approved,
    Rejected,
    Disabled,
    Enabled,
    Offboarded,
}

impl EwsAuditEvent {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Edited => "edited",
            Self::Cancelled => "cancelled",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
            Self::Disabled => "disabled",
            Self::Enabled => "enabled",
            Self::Offboarded => "offboarded",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "submitted" => Some(Self::Submitted),
            "edited" => Some(Self::Edited),
            "cancelled" => Some(Self::Cancelled),
            "approved" => Some(Self::Approved),
            "rejected" => Some(Self::Rejected),
            "disabled" => Some(Self::Disabled),
            "enabled" => Some(Self::Enabled),
            "offboarded" => Some(Self::Offboarded),
            _ => None,
        }
    }
}

/// Audit log row read from the database.
#[derive(Debug, Clone, Queryable, Selectable, Identifiable)]
#[diesel(table_name = ews_audit_log)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct EwsAuditLog {
    pub id: i64,
    pub ews_uuid: Option<Uuid>,
    pub request_uuid: Option<Uuid>,
    pub event: String,
    pub actor_user_id: Option<i32>,
    pub actor_username: String,
    pub target_user_id: Option<i32>,
    pub target_username: String,
    pub ews_name: String,
    pub public_key_fingerprint: String,
    pub decision_reason: Option<String>,
    pub actor_ip: Option<IpNetwork>,
    pub request_id: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl EwsAuditLog {
    pub fn event_typed(&self) -> Option<EwsAuditEvent> {
        EwsAuditEvent::parse(&self.event)
    }
}

/// New audit row prepared for insertion. Always inserted from
/// `vauban-access` inside the transaction that owns the state change
/// (never standalone from `vauban-web`).
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = ews_audit_log)]
pub struct NewEwsAuditLog {
    pub ews_uuid: Option<Uuid>,
    pub request_uuid: Option<Uuid>,
    pub event: String,
    pub actor_user_id: Option<i32>,
    pub actor_username: String,
    pub target_user_id: Option<i32>,
    pub target_username: String,
    pub ews_name: String,
    pub public_key_fingerprint: String,
    pub decision_reason: Option<String>,
    pub actor_ip: Option<IpNetwork>,
    pub request_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ews_audit_event_roundtrip_all_variants() {
        for v in [
            EwsAuditEvent::Submitted,
            EwsAuditEvent::Edited,
            EwsAuditEvent::Cancelled,
            EwsAuditEvent::Approved,
            EwsAuditEvent::Rejected,
            EwsAuditEvent::Disabled,
            EwsAuditEvent::Enabled,
            EwsAuditEvent::Offboarded,
        ] {
            assert_eq!(EwsAuditEvent::parse(v.as_str()), Some(v));
        }
    }

    #[test]
    fn ews_audit_event_parse_unknown_returns_none() {
        assert_eq!(EwsAuditEvent::parse("SUBMITTED"), None);
        assert_eq!(EwsAuditEvent::parse(""), None);
        assert_eq!(EwsAuditEvent::parse("approve"), None);
    }

    #[test]
    fn ews_audit_event_as_str_is_lowercase_ascii() {
        for v in [
            EwsAuditEvent::Submitted,
            EwsAuditEvent::Edited,
            EwsAuditEvent::Cancelled,
            EwsAuditEvent::Approved,
            EwsAuditEvent::Rejected,
            EwsAuditEvent::Disabled,
            EwsAuditEvent::Enabled,
            EwsAuditEvent::Offboarded,
        ] {
            assert!(v.as_str().bytes().all(|b| b.is_ascii_lowercase()));
        }
    }
}
