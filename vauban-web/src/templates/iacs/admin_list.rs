//! Admin-zone IACS landing page (`GET /iacs/admin`).
//!
//! Aggregates two distinct collections in a single page so an admin
//! can review the entire IACS surface at a glance:
//!
//! 1. Pending onboarding requests -- the operationally hot section,
//!    rendered with Approve / Reject controls (separation of duties
//!    not enforced for IACS today: the requester can be the admin
//!    of last resort, but a future iteration may add an `is_own`
//!    flag analogous to the JIT approval flow).
//! 2. Active / disabled EWS -- the lifecycle section: Disable,
//!    Re-enable, Offboard.
//!
//! A small "history" tab is intentionally NOT rendered here -- the
//! detail page already shows all decision-related fields, and the
//! audit log is queried separately in the runbook tooling.

use askama::Template;

use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};

/// Pending onboarding-request row.
#[derive(Debug, Clone)]
pub struct AdminPendingRequest {
    pub request_uuid: String,
    pub requester_username: String,
    pub ews_name: String,
    pub key_algo: String,
    pub fingerprint_short: String,
    pub justification: String,
    pub created_at: String,
}

/// Active / disabled / offboarded EWS row.
#[derive(Debug, Clone)]
pub struct AdminEwsRow {
    pub ews_uuid: String,
    pub owner_username: String,
    pub name: String,
    pub key_algo: String,
    pub fingerprint_short: String,
    /// `active` | `disabled` | `offboarded`. Pinned as a string so
    /// the template can branch with simple equality checks.
    pub state: String,
    pub created_at: String,
    pub disabled_at: Option<String>,
    pub offboarded_at: Option<String>,
}

impl AdminEwsRow {
    pub fn is_active(&self) -> bool {
        self.state == "active"
    }
    pub fn is_disabled(&self) -> bool {
        self.state == "disabled"
    }
    pub fn is_offboarded(&self) -> bool {
        self.state == "offboarded"
    }
    pub fn state_class(&self) -> &'static str {
        match self.state.as_str() {
            "active" => "bg-green-100 text-green-800 dark:bg-green-900/50 dark:text-green-300",
            "disabled" => "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300",
            "offboarded" => {
                "bg-orange-100 text-orange-800 dark:bg-orange-900/50 dark:text-orange-300"
            }
            _ => "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300",
        }
    }
}

#[derive(Template)]
#[template(path = "iacs/admin_list.html")]
pub struct AdminListTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub csrf_token: String,
    pub pending_requests: Vec<AdminPendingRequest>,
    pub ews_rows: Vec<AdminEwsRow>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> AdminListTemplate {
        AdminListTemplate {
            title: "IACS".into(),
            user: Some(UserContext {
                uuid: "u".into(),
                username: "admin".into(),
                display_name: "Admin".into(),
                is_superuser: true,
                is_staff: true,
            }),
            vauban: VaubanConfig::default(),
            messages: Vec::new(),
            language_code: "en".into(),
            sidebar_content: None,
            header_user: None,
            csrf_token: "tk".into(),
            pending_requests: vec![AdminPendingRequest {
                request_uuid: "00000000-0000-0000-0000-000000000001".into(),
                requester_username: "alice".into(),
                ews_name: "factory-ews-01".into(),
                key_algo: "ssh-ed25519".into(),
                fingerprint_short: "abcdef0123456789".into(),
                justification: "New onboarding for factory line 7".into(),
                created_at: "May 6, 2026 10:00".into(),
            }],
            ews_rows: vec![
                AdminEwsRow {
                    ews_uuid: "00000000-0000-0000-0000-000000000002".into(),
                    owner_username: "bob".into(),
                    name: "factory-ews-02".into(),
                    key_algo: "ssh-ed25519".into(),
                    fingerprint_short: "1111222233334444".into(),
                    state: "active".into(),
                    created_at: "May 1, 2026 09:00".into(),
                    disabled_at: None,
                    offboarded_at: None,
                },
                AdminEwsRow {
                    ews_uuid: "00000000-0000-0000-0000-000000000003".into(),
                    owner_username: "carol".into(),
                    name: "factory-ews-03".into(),
                    key_algo: "ssh-ed25519".into(),
                    fingerprint_short: "5555666677778888".into(),
                    state: "disabled".into(),
                    created_at: "Apr 14, 2026 09:00".into(),
                    disabled_at: Some("May 2, 2026 12:00".into()),
                    offboarded_at: None,
                },
            ],
        }
    }

    #[test]
    fn admin_list_renders() {
        let html = fixture().render().expect("render");
        assert!(html.contains("Pending onboarding requests"));
        assert!(html.contains("alice"));
        assert!(html.contains("/iacs/admin/request/00000000-0000-0000-0000-000000000001/approve"));
        assert!(html.contains("/iacs/admin/request/00000000-0000-0000-0000-000000000001/reject"));
    }

    #[test]
    fn ews_active_renders_disable_and_offboard() {
        let html = fixture().render().expect("render");
        assert!(html.contains("/iacs/admin/ews/00000000-0000-0000-0000-000000000002/disable"));
        assert!(html.contains("/iacs/admin/ews/00000000-0000-0000-0000-000000000002/offboard"));
        assert!(!html.contains("/iacs/admin/ews/00000000-0000-0000-0000-000000000002/enable"));
    }

    #[test]
    fn ews_disabled_renders_enable_only() {
        let html = fixture().render().expect("render");
        assert!(html.contains("/iacs/admin/ews/00000000-0000-0000-0000-000000000003/enable"));
        assert!(html.contains("/iacs/admin/ews/00000000-0000-0000-0000-000000000003/offboard"));
        assert!(!html.contains("/iacs/admin/ews/00000000-0000-0000-0000-000000000003/disable"));
    }

    #[test]
    fn empty_state_renders() {
        let mut tpl = fixture();
        tpl.pending_requests.clear();
        tpl.ews_rows.clear();
        let html = tpl.render().expect("render");
        assert!(html.contains("No pending requests"));
        assert!(html.contains("No EWS"));
    }

    #[test]
    fn helpers_match_state() {
        let row = AdminEwsRow {
            ews_uuid: "x".into(),
            owner_username: "y".into(),
            name: "z".into(),
            key_algo: "ssh-ed25519".into(),
            fingerprint_short: "fp".into(),
            state: "active".into(),
            created_at: "now".into(),
            disabled_at: None,
            offboarded_at: None,
        };
        assert!(row.is_active());
        assert!(!row.is_disabled());
        assert!(!row.is_offboarded());
        assert!(row.state_class().contains("green"));
    }
}
