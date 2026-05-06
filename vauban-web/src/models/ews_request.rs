//! Engineering Workstation (EWS) onboarding request model.
//!
//! A request goes through one of four terminal states from `pending`:
//!
//!   - `approved`  -- an admin signed off; a row is also created in `ews`.
//!   - `rejected`  -- an admin refused; `decision_reason` is mandatory.
//!   - `cancelled` -- the requester withdrew their pending request.
//!
//! Once a request leaves `pending`, it cannot be UPDATEd back. The schema
//! check constraint `ews_request_decision_consistency` enforces this; the
//! `vauban-access` `iacs` handlers add an in-transaction `status = pending`
//! re-check (TOCTOU defense). Re-submissions create a NEW request row;
//! the historical row stays for audit.

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::schema::ews_onboarding_requests;

/// Lifecycle state of an `ews_onboarding_requests` row.
///
/// Mirrors the DB-level CHECK constraint
/// `ews_onboarding_requests_status_check`. Adding a variant here MUST come
/// with a migration that relaxes the CHECK and updates every code path
/// that pattern-matches on the literal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EwsRequestStatus {
    Pending,
    Approved,
    Rejected,
    Cancelled,
}

impl EwsRequestStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Self::Pending),
            "approved" => Some(Self::Approved),
            "rejected" => Some(Self::Rejected),
            "cancelled" => Some(Self::Cancelled),
            _ => None,
        }
    }

    pub fn is_terminal(self) -> bool {
        !matches!(self, Self::Pending)
    }
}

/// Onboarding request row read from the database.
#[derive(Debug, Clone, Queryable, Selectable, Identifiable)]
#[diesel(table_name = ews_onboarding_requests)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct EwsRequest {
    pub id: i64,
    pub uuid: Uuid,
    pub user_id: i32,
    pub name: String,
    pub public_key: String,
    pub public_key_fingerprint: String,
    pub key_algo: String,
    pub justification: String,
    pub status: String,
    pub decision_reason: Option<String>,
    pub decided_by_id: Option<i32>,
    pub decided_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl EwsRequest {
    /// Typed accessor with defensive fallback to `Pending` if a manual SQL
    /// edit inserted an unknown literal (the CHECK should prevent it).
    pub fn status_typed(&self) -> EwsRequestStatus {
        EwsRequestStatus::parse(&self.status).unwrap_or(EwsRequestStatus::Pending)
    }
}

/// New request row prepared for insertion. The caller MUST validate the
/// public key (algo whitelist, fingerprint computation) before
/// constructing this; see `crate::services::iacs::parse_and_validate_public_key`.
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = ews_onboarding_requests)]
pub struct NewEwsRequest {
    pub user_id: i32,
    pub name: String,
    pub public_key: String,
    pub public_key_fingerprint: String,
    pub key_algo: String,
    pub justification: String,
}

/// Update applied to a pending request (edit). Only the user-controlled
/// fields are mutable; the lifecycle columns are out of reach. Decision
/// updates use a separate path inside `vauban-access` so the trigger and
/// CHECK constraints catch any drift.
#[derive(Debug, Clone, AsChangeset)]
#[diesel(table_name = ews_onboarding_requests)]
pub struct EditEwsRequestChange {
    pub name: String,
    pub public_key: String,
    pub public_key_fingerprint: String,
    pub key_algo: String,
    pub justification: String,
    pub updated_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ews_request_status_roundtrip_all_variants() {
        for v in [
            EwsRequestStatus::Pending,
            EwsRequestStatus::Approved,
            EwsRequestStatus::Rejected,
            EwsRequestStatus::Cancelled,
        ] {
            assert_eq!(EwsRequestStatus::parse(v.as_str()), Some(v));
        }
    }

    #[test]
    fn ews_request_status_parse_unknown_returns_none() {
        assert_eq!(EwsRequestStatus::parse("PENDING"), None);
        assert_eq!(EwsRequestStatus::parse(""), None);
        assert_eq!(EwsRequestStatus::parse("approve"), None);
    }

    #[test]
    fn ews_request_status_as_str_is_lowercase_ascii() {
        for v in [
            EwsRequestStatus::Pending,
            EwsRequestStatus::Approved,
            EwsRequestStatus::Rejected,
            EwsRequestStatus::Cancelled,
        ] {
            assert!(v.as_str().bytes().all(|b| b.is_ascii_lowercase()));
        }
    }

    #[test]
    fn ews_request_status_is_terminal_classification() {
        assert!(!EwsRequestStatus::Pending.is_terminal());
        assert!(EwsRequestStatus::Approved.is_terminal());
        assert!(EwsRequestStatus::Rejected.is_terminal());
        assert!(EwsRequestStatus::Cancelled.is_terminal());
    }
}
