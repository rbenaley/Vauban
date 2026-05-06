//! Admin-zone IACS detail page.
//!
//! Two flavours:
//!
//! 1. `RequestDetail` -- a row from `ews_onboarding_requests`. Pending
//!    rows expose Approve / Reject; decided rows render the decision
//!    block (decided_by, decided_at, optional reason).
//! 2. `EwsDetail` -- a row from `ews`. Exposes Disable / Enable /
//!    Offboard depending on the lifecycle state.
//!
//! Both flavours share the same outer template + base layout; the
//! variant is encoded as a tagged enum so the template branches on
//! `kind == "request"` vs `kind == "ews"`.

use askama::Template;

use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};

/// Detail of a single onboarding request (any status).
#[derive(Debug, Clone)]
pub struct RequestDetail {
    pub request_uuid: String,
    pub requester_username: String,
    pub requester_email: Option<String>,
    pub ews_name: String,
    pub key_algo: String,
    pub fingerprint_short: String,
    pub fingerprint_full: String,
    /// Full OpenSSH-formatted public key (`ssh-ed25519 base64...`)
    /// rendered inside a modal so the admin can copy-paste it for
    /// audit / verification. Never auto-displayed; click-to-show.
    pub full_public_key: String,
    pub justification: String,
    /// `pending` | `approved` | `rejected` | `cancelled`.
    pub status: String,
    pub created_at: String,
    pub decided_at: Option<String>,
    pub decided_by_username: Option<String>,
    pub decision_reason: Option<String>,
}

impl RequestDetail {
    pub fn is_pending(&self) -> bool {
        self.status == "pending"
    }
    pub fn is_approved(&self) -> bool {
        self.status == "approved"
    }
    pub fn is_rejected(&self) -> bool {
        self.status == "rejected"
    }
    pub fn is_cancelled(&self) -> bool {
        self.status == "cancelled"
    }
    pub fn status_class(&self) -> &'static str {
        match self.status.as_str() {
            "pending" => "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/50 dark:text-yellow-300",
            "approved" => "bg-green-100 text-green-800 dark:bg-green-900/50 dark:text-green-300",
            "rejected" => "bg-red-100 text-red-800 dark:bg-red-900/50 dark:text-red-300",
            "cancelled" => "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300",
            _ => "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300",
        }
    }
}

/// Detail of a single EWS row (any lifecycle state).
#[derive(Debug, Clone)]
pub struct EwsDetail {
    pub ews_uuid: String,
    pub owner_username: String,
    pub owner_email: Option<String>,
    pub name: String,
    pub key_algo: String,
    pub fingerprint_short: String,
    pub fingerprint_full: String,
    pub full_public_key: String,
    /// `active` | `disabled` | `offboarded`.
    pub state: String,
    pub created_at: String,
    pub disabled_at: Option<String>,
    pub disabled_by_username: Option<String>,
    pub offboarded_at: Option<String>,
    pub offboarded_by_username: Option<String>,
}

impl EwsDetail {
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

/// Tagged-union detail template. The two flavours share enough
/// chrome (breadcrumbs, header, key modal) that a single template
/// file is simpler than two near-identical ones.
#[derive(Template)]
#[template(path = "iacs/admin_detail.html")]
pub struct AdminDetailTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub csrf_token: String,
    /// `request` or `ews` -- discriminator for the template.
    pub kind: String,
    pub request: Option<RequestDetail>,
    pub ews: Option<EwsDetail>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(status: &str) -> RequestDetail {
        RequestDetail {
            request_uuid: "00000000-0000-0000-0000-000000000001".into(),
            requester_username: "alice".into(),
            requester_email: Some("alice@example.com".into()),
            ews_name: "factory-ews-01".into(),
            key_algo: "ssh-ed25519".into(),
            fingerprint_short: "abcd1234".into(),
            fingerprint_full: "abcd1234".repeat(8),
            full_public_key: "ssh-ed25519 AAAA".into(),
            justification: "Onboarding new EWS".into(),
            status: status.into(),
            created_at: "May 6, 2026 10:00".into(),
            decided_at: None,
            decided_by_username: None,
            decision_reason: None,
        }
    }

    fn ews(state: &str) -> EwsDetail {
        EwsDetail {
            ews_uuid: "00000000-0000-0000-0000-000000000002".into(),
            owner_username: "bob".into(),
            owner_email: Some("bob@example.com".into()),
            name: "factory-ews-02".into(),
            key_algo: "ssh-ed25519".into(),
            fingerprint_short: "fedc4321".into(),
            fingerprint_full: "fedc4321".repeat(8),
            full_public_key: "ssh-ed25519 BBBB".into(),
            state: state.into(),
            created_at: "May 1, 2026 09:00".into(),
            disabled_at: None,
            disabled_by_username: None,
            offboarded_at: None,
            offboarded_by_username: None,
        }
    }

    fn template_for_request(r: RequestDetail) -> AdminDetailTemplate {
        AdminDetailTemplate {
            title: "IACS request".into(),
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
            kind: "request".into(),
            request: Some(r),
            ews: None,
        }
    }

    fn template_for_ews(e: EwsDetail) -> AdminDetailTemplate {
        AdminDetailTemplate {
            title: "IACS EWS".into(),
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
            kind: "ews".into(),
            request: None,
            ews: Some(e),
        }
    }

    #[test]
    fn pending_request_shows_approve_and_reject_forms() {
        let html = template_for_request(req("pending"))
            .render()
            .expect("render");
        assert!(html.contains("/iacs/admin/request/00000000-0000-0000-0000-000000000001/approve"));
        assert!(html.contains("/iacs/admin/request/00000000-0000-0000-0000-000000000001/reject"));
    }

    #[test]
    fn approved_request_hides_action_forms_and_shows_decision_block() {
        let mut r = req("approved");
        r.decided_at = Some("May 6, 2026 11:00".into());
        r.decided_by_username = Some("admin".into());
        let html = template_for_request(r).render().expect("render");
        assert!(!html.contains("/approve"));
        assert!(!html.contains("/reject"));
        assert!(html.contains("Approved by"));
        assert!(html.contains("admin"));
    }

    #[test]
    fn rejected_request_shows_reason() {
        let mut r = req("rejected");
        r.decided_at = Some("May 6, 2026 11:30".into());
        r.decided_by_username = Some("admin".into());
        r.decision_reason = Some("Key rotation policy".into());
        let html = template_for_request(r).render().expect("render");
        assert!(html.contains("Rejected by"));
        assert!(html.contains("Key rotation policy"));
    }

    #[test]
    fn active_ews_shows_disable_and_offboard_only() {
        let html = template_for_ews(ews("active")).render().expect("render");
        assert!(html.contains("/iacs/admin/ews/00000000-0000-0000-0000-000000000002/disable"));
        assert!(html.contains("/iacs/admin/ews/00000000-0000-0000-0000-000000000002/offboard"));
        assert!(!html.contains("/iacs/admin/ews/00000000-0000-0000-0000-000000000002/enable"));
    }

    #[test]
    fn disabled_ews_shows_enable_and_offboard_only() {
        let html = template_for_ews(ews("disabled")).render().expect("render");
        assert!(html.contains("/iacs/admin/ews/00000000-0000-0000-0000-000000000002/enable"));
        assert!(html.contains("/iacs/admin/ews/00000000-0000-0000-0000-000000000002/offboard"));
        assert!(!html.contains("/iacs/admin/ews/00000000-0000-0000-0000-000000000002/disable"));
    }

    #[test]
    fn offboarded_ews_shows_no_action_forms() {
        let html = template_for_ews(ews("offboarded"))
            .render()
            .expect("render");
        assert!(!html.contains("/disable"));
        assert!(!html.contains("/enable"));
        assert!(!html.contains("/offboard\""));
    }

    #[test]
    fn full_public_key_modal_is_present_in_request_detail() {
        let html = template_for_request(req("pending"))
            .render()
            .expect("render");
        assert!(html.contains("Full public key"));
    }

    #[test]
    fn full_public_key_modal_is_present_in_ews_detail() {
        let html = template_for_ews(ews("active")).render().expect("render");
        assert!(html.contains("Full public key"));
    }
}
