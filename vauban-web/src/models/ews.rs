//! Approved Engineering Workstation (EWS) model.
//!
//! An `ews` row exists exactly once per approved `ews_onboarding_requests`
//! row (1:1 via `request_uuid`). The lifecycle is encoded in two
//! independent columns:
//!
//!   - `disabled_at` -- non-NULL means the EWS is suspended (reversible
//!     via `enable`). Disabling does NOT free the public-key fingerprint
//!     (the partial unique index `ews_active_fingerprint_uniq` covers
//!     active + disabled rows).
//!
//!   - `offboarded_at` -- non-NULL means the EWS is permanently retired
//!     (irreversible soft-delete). Offboarding releases the fingerprint;
//!     the user can re-submit the same key.
//!
//! Both columns can be set at the same time (offboard wins semantically).
//! The `EwsState::derive` helper collapses the two columns into a single
//! enum for templates and policy decisions.

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::schema::ews;

/// Derived lifecycle state of an `ews` row. Computed from
/// `disabled_at` / `offboarded_at`; never persisted as a separate column
/// to keep the DB schema minimal and racefree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EwsState {
    Active,
    Disabled,
    Offboarded,
}

impl EwsState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
            Self::Offboarded => "offboarded",
        }
    }

    /// Derive the state from the two soft-delete columns.
    /// Offboarding wins over disabled (an EWS that was disabled then
    /// offboarded shows as offboarded, never goes back).
    pub fn derive(
        disabled_at: Option<DateTime<Utc>>,
        offboarded_at: Option<DateTime<Utc>>,
    ) -> Self {
        if offboarded_at.is_some() {
            Self::Offboarded
        } else if disabled_at.is_some() {
            Self::Disabled
        } else {
            Self::Active
        }
    }

    pub fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }
}

/// Approved EWS row read from the database.
#[derive(Debug, Clone, Queryable, Selectable, Identifiable)]
#[diesel(table_name = ews)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Ews {
    pub id: i64,
    pub uuid: Uuid,
    pub request_uuid: Uuid,
    pub user_id: i32,
    pub name: String,
    pub public_key: String,
    pub public_key_fingerprint: String,
    pub key_algo: String,
    pub disabled_by_id: Option<i32>,
    pub disabled_at: Option<DateTime<Utc>>,
    pub offboarded_by_id: Option<i32>,
    pub offboarded_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Ews {
    /// Derived state -- single source of truth for templates / policy.
    pub fn state(&self) -> EwsState {
        EwsState::derive(self.disabled_at, self.offboarded_at)
    }
}

/// New approved EWS row prepared for insertion (called from the
/// `RecordEwsDecision Approve` transaction inside `vauban-access`,
/// never directly from `vauban-web`).
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = ews)]
pub struct NewEws {
    pub request_uuid: Uuid,
    pub user_id: i32,
    pub name: String,
    pub public_key: String,
    pub public_key_fingerprint: String,
    pub key_algo: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts() -> DateTime<Utc> {
        Utc::now()
    }

    #[test]
    fn ews_state_active_when_both_null() {
        assert_eq!(EwsState::derive(None, None), EwsState::Active);
    }

    #[test]
    fn ews_state_disabled_when_only_disabled_at_set() {
        assert_eq!(EwsState::derive(Some(ts()), None), EwsState::Disabled);
    }

    #[test]
    fn ews_state_offboarded_when_offboarded_at_set() {
        assert_eq!(EwsState::derive(None, Some(ts())), EwsState::Offboarded);
    }

    #[test]
    fn ews_state_offboarded_wins_over_disabled() {
        let now = ts();
        assert_eq!(EwsState::derive(Some(now), Some(now)), EwsState::Offboarded);
    }

    #[test]
    fn ews_state_as_str_is_lowercase_ascii() {
        for v in [EwsState::Active, EwsState::Disabled, EwsState::Offboarded] {
            assert!(v.as_str().bytes().all(|b| b.is_ascii_lowercase()));
        }
    }

    #[test]
    fn ews_state_is_active_only_for_active() {
        assert!(EwsState::Active.is_active());
        assert!(!EwsState::Disabled.is_active());
        assert!(!EwsState::Offboarded.is_active());
    }
}
