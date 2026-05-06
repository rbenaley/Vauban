//! IACS / EWS onboarding templates.
//!
//! Two surfaces today:
//!
//! 1. [`onboard_form::OnboardFormTemplate`] -- the user-zone
//!    `GET /iacs/onboard` form (reused by the edit-pending flow,
//!    which simply pre-fills `prefill`).
//! 2. [`MyEwsItem`] -- a row rendered inside the "My EWS" section of
//!    `/sessions/my-requests`. Lives here (not in `sessions/`) because
//!    it is owned by the IACS handlers; the `MyRequestsTemplate` only
//!    aggregates a `Vec<MyEwsItem>` it does not interpret.
//!
//! Admin-zone templates (list / detail / decision modals) land in
//! palier 7.

pub mod admin_detail;
pub mod admin_list;
pub mod onboard_form;

pub use admin_detail::{AdminDetailTemplate, EwsDetail, RequestDetail};
pub use admin_list::{AdminEwsRow, AdminListTemplate, AdminPendingRequest};
pub use onboard_form::{OnboardFormPrefill, OnboardFormTemplate};

/// Display state of an EWS row from the user's perspective. Derived
/// from the `(disabled_at, offboarded_at)` snapshot plus the upstream
/// onboarding-request status.
///
/// Pinned as a string so templates can render badge classes by
/// equality without exposing the Rust enum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MyEwsState {
    Pending,
    Rejected,
    Cancelled,
    Active,
    Disabled,
    Offboarded,
}

impl MyEwsState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Rejected => "rejected",
            Self::Cancelled => "cancelled",
            Self::Active => "active",
            Self::Disabled => "disabled",
            Self::Offboarded => "offboarded",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Pending => "Pending",
            Self::Rejected => "Rejected",
            Self::Cancelled => "Cancelled",
            Self::Active => "Active",
            Self::Disabled => "Disabled",
            Self::Offboarded => "Offboarded",
        }
    }

    pub fn badge_class(&self) -> &'static str {
        match self {
            Self::Pending => {
                "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/50 dark:text-yellow-300"
            }
            Self::Rejected | Self::Cancelled => {
                "bg-red-100 text-red-800 dark:bg-red-900/50 dark:text-red-300"
            }
            Self::Active => "bg-green-100 text-green-800 dark:bg-green-900/50 dark:text-green-300",
            Self::Disabled => "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300",
            Self::Offboarded => {
                "bg-orange-100 text-orange-800 dark:bg-orange-900/50 dark:text-orange-300"
            }
        }
    }
}

/// One row in the "My EWS" section of `/sessions/my-requests`.
///
/// The struct mirrors the columns the template renders: the source of
/// truth (`ews` / `ews_onboarding_requests` rows) lives in the
/// handler, which projects them down to this view-model.
#[derive(Debug, Clone)]
pub struct MyEwsItem {
    /// `ews_onboarding_requests.uuid` for pending / rejected /
    /// cancelled rows; `ews.uuid` for approved / disabled / offboarded
    /// rows. The template uses it for `edit` / `cancel` /
    /// `offboard-self` form actions, which know which collection the
    /// uuid refers to via the `state`.
    pub uuid: String,
    pub name: String,
    pub fingerprint_short: String,
    pub key_algo: String,
    pub state: MyEwsState,
    pub created_at: String,
    pub decided_at: Option<String>,
    /// Decision reason for rejected requests. `None` for any other
    /// state.
    pub rejection_reason: Option<String>,
    /// Justification supplied at submit-time (only relevant for
    /// pending / rejected / cancelled rows).
    pub justification: Option<String>,
}

impl MyEwsItem {
    pub fn state_str(&self) -> &'static str {
        self.state.as_str()
    }
    pub fn state_label(&self) -> &'static str {
        self.state.label()
    }
    pub fn state_class(&self) -> &'static str {
        self.state.badge_class()
    }
    pub fn is_pending(&self) -> bool {
        self.state == MyEwsState::Pending
    }
    pub fn is_active(&self) -> bool {
        self.state == MyEwsState::Active
    }
    pub fn is_disabled(&self) -> bool {
        self.state == MyEwsState::Disabled
    }
    /// Owner-actionable today: only pending and active. Disabled keys
    /// are admin-recoverable; offboarded is irreversible.
    pub fn allows_self_offboard(&self) -> bool {
        self.is_active()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(state: MyEwsState) -> MyEwsItem {
        MyEwsItem {
            uuid: "00000000-0000-0000-0000-000000000001".into(),
            name: "factory-ews-01".into(),
            fingerprint_short: "ab12cd34ef56".into(),
            key_algo: "ssh-ed25519".into(),
            state,
            created_at: "May 6, 2026 10:00".into(),
            decided_at: None,
            rejection_reason: None,
            justification: None,
        }
    }

    #[test]
    fn state_str_round_trips() {
        for s in [
            MyEwsState::Pending,
            MyEwsState::Rejected,
            MyEwsState::Cancelled,
            MyEwsState::Active,
            MyEwsState::Disabled,
            MyEwsState::Offboarded,
        ] {
            assert!(!s.as_str().is_empty());
            assert!(!s.label().is_empty());
            assert!(!s.badge_class().is_empty());
        }
    }

    #[test]
    fn pending_is_actionable_for_cancel_only() {
        let item = sample(MyEwsState::Pending);
        assert!(item.is_pending());
        assert!(!item.is_active());
        assert!(!item.allows_self_offboard());
    }

    #[test]
    fn active_is_actionable_for_self_offboard() {
        let item = sample(MyEwsState::Active);
        assert!(item.is_active());
        assert!(item.allows_self_offboard());
    }

    #[test]
    fn disabled_is_not_owner_actionable() {
        let item = sample(MyEwsState::Disabled);
        assert!(item.is_disabled());
        assert!(!item.allows_self_offboard());
    }

    #[test]
    fn offboarded_is_terminal() {
        let item = sample(MyEwsState::Offboarded);
        assert!(!item.is_pending());
        assert!(!item.is_active());
        assert!(!item.allows_self_offboard());
    }

    #[test]
    fn badge_classes_are_distinct_per_state() {
        let pending = sample(MyEwsState::Pending);
        let active = sample(MyEwsState::Active);
        let offboarded = sample(MyEwsState::Offboarded);
        assert_ne!(pending.state_class(), active.state_class());
        assert_ne!(active.state_class(), offboarded.state_class());
    }
}
