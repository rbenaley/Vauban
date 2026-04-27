use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};
/// VAUBAN Web - Approval detail template.
use askama::Template;

/// Approval detail data.
#[derive(Debug, Clone)]
pub struct ApprovalDetail {
    pub uuid: String,
    pub username: String,
    pub user_email: String,
    pub asset_name: String,
    pub asset_type: String,
    pub asset_hostname: String,
    pub session_type: String,
    pub status: String,
    pub justification: Option<String>,
    pub client_ip: String,
    pub credential_username: String,
    pub created_at: String,
    pub is_recorded: bool,
    pub max_session_duration: Option<i32>,
    /// True when the requester is the viewer; the detail template
    /// hides Approve/Reject controls in that case (separation of
    /// duties — see `ApprovalListItem::is_own`).
    pub is_own: bool,
    /// Username of the admin who approved or rejected this request (if decided).
    pub decided_by: Option<String>,
    /// Timestamp of the decision (formatted for display).
    pub decided_at: Option<String>,
    /// Reason supplied by the decision-maker (if any).
    pub decision_reason: Option<String>,
}

impl ApprovalDetail {
    /// Get status badge class.
    pub fn status_class(&self) -> &str {
        super::session_status_class(&self.status)
    }

    /// Check if pending.
    pub fn is_pending(&self) -> bool {
        self.status == "pending"
    }

    /// Human-readable duration display (e.g. "2h", "30min", "Unlimited").
    pub fn duration_display(&self) -> String {
        crate::utils::duration_display(self.max_session_duration)
    }

    /// Default value for the duration input field (in the natural unit).
    pub fn duration_default_value(&self) -> Option<i32> {
        crate::utils::duration_to_value_unit(self.max_session_duration).0
    }

    /// Default unit for the duration select ("hours" or "minutes").
    pub fn duration_default_unit(&self) -> &str {
        crate::utils::duration_to_value_unit(self.max_session_duration).1
    }
}

#[derive(Template)]
#[template(path = "sessions/approval_detail.html")]
pub struct ApprovalDetailTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub approval: ApprovalDetail,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_approval_detail(status: &str) -> ApprovalDetail {
        ApprovalDetail {
            uuid: "approval-uuid".to_string(),
            username: "testuser".to_string(),
            user_email: "test@example.com".to_string(),
            asset_name: "Test Server".to_string(),
            asset_type: "linux".to_string(),
            asset_hostname: "test.example.com".to_string(),
            session_type: "ssh".to_string(),
            status: status.to_string(),
            justification: Some("Need access for maintenance".to_string()),
            client_ip: "192.168.1.100".to_string(),
            credential_username: "admin".to_string(),
            created_at: "2026-01-03 10:00:00".to_string(),
            is_recorded: true,
            max_session_duration: Some(7200),
            is_own: false,
            decided_by: None,
            decided_at: None,
            decision_reason: None,
        }
    }

    // Tests for status_class()
    #[test]
    fn test_status_class_pending() {
        let detail = create_test_approval_detail("pending");
        assert!(detail.status_class().contains("yellow"));
    }

    #[test]
    fn test_status_class_approved() {
        let detail = create_test_approval_detail("approved");
        assert!(detail.status_class().contains("green"));
    }

    #[test]
    fn test_status_class_rejected() {
        let detail = create_test_approval_detail("rejected");
        assert!(detail.status_class().contains("red"));
    }

    #[test]
    fn test_status_class_expired() {
        let detail = create_test_approval_detail("expired");
        assert!(detail.status_class().contains("gray"));
    }

    #[test]
    fn test_status_class_orphaned() {
        let detail = create_test_approval_detail("orphaned");
        assert!(detail.status_class().contains("gray"));
    }

    #[test]
    fn test_status_class_unknown() {
        let detail = create_test_approval_detail("unknown");
        assert!(detail.status_class().contains("gray"));
    }

    // Tests for is_pending()
    #[test]
    fn test_is_pending_true() {
        let detail = create_test_approval_detail("pending");
        assert!(detail.is_pending());
    }

    #[test]
    fn test_is_pending_false() {
        let detail = create_test_approval_detail("approved");
        assert!(!detail.is_pending());
    }

    // Tests for ApprovalDetail struct
    #[test]
    fn test_approval_detail_creation() {
        let detail = create_test_approval_detail("pending");
        assert_eq!(detail.username, "testuser");
        assert!(detail.is_recorded);
    }

    #[test]
    fn test_approval_detail_without_justification() {
        let mut detail = create_test_approval_detail("pending");
        detail.justification = None;
        assert!(detail.justification.is_none());
    }

    #[test]
    fn test_approval_detail_clone() {
        let detail = create_test_approval_detail("approved");
        let cloned = detail.clone();
        assert_eq!(detail.uuid, cloned.uuid);
    }

    // ---- duration helpers tests ----

    #[test]
    fn test_duration_display_hours() {
        let mut detail = create_test_approval_detail("pending");
        detail.max_session_duration = Some(7200);
        assert_eq!(detail.duration_display(), "2h");
    }

    #[test]
    fn test_duration_display_minutes() {
        let mut detail = create_test_approval_detail("pending");
        detail.max_session_duration = Some(1800);
        assert_eq!(detail.duration_display(), "30min");
    }

    #[test]
    fn test_duration_display_unlimited() {
        let mut detail = create_test_approval_detail("pending");
        detail.max_session_duration = None;
        assert_eq!(detail.duration_display(), "Unlimited");
    }

    #[test]
    fn test_duration_default_value_hours() {
        let mut detail = create_test_approval_detail("pending");
        detail.max_session_duration = Some(7200);
        assert_eq!(detail.duration_default_value(), Some(2));
    }

    #[test]
    fn test_duration_default_unit_hours() {
        let mut detail = create_test_approval_detail("pending");
        detail.max_session_duration = Some(7200);
        assert_eq!(detail.duration_default_unit(), "hours");
    }

    #[test]
    fn test_duration_default_unit_minutes() {
        let mut detail = create_test_approval_detail("pending");
        detail.max_session_duration = Some(1800);
        assert_eq!(detail.duration_default_unit(), "minutes");
    }

    // ---- UI gating tests (Tier 4) — separation of duties ----
    //
    // The detail page must visibly suppress the Approve/Reject
    // buttons when the requester is the viewer, and replace them by
    // an explanatory pill. The DB CHECK + IPC layer already block
    // the POST; the UI block is what prevents accidental clicks.

    fn detail_template(is_own: bool) -> ApprovalDetailTemplate {
        use crate::templates::base::{UserContext, VaubanConfig};
        let mut a = create_test_approval_detail("pending");
        a.uuid = "uuid-detail-1".to_string();
        a.is_own = is_own;
        ApprovalDetailTemplate {
            title: "Detail".to_string(),
            user: Some(UserContext {
                uuid: "x".to_string(),
                username: "x".to_string(),
                display_name: "x".to_string(),
                is_superuser: false,
                is_staff: false,
            }),
            vauban: VaubanConfig::default(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
            approval: a,
        }
    }

    #[test]
    fn ui_gating_detail_hides_buttons_for_own_pending() {
        let html = detail_template(true).render().expect("render");
        assert!(
            !html.contains("/sessions/approvals/uuid-detail-1/approve"),
            "own pending detail must NOT expose Approve form"
        );
        assert!(
            !html.contains("/sessions/approvals/uuid-detail-1/reject"),
            "own pending detail must NOT expose Reject form"
        );
        assert!(
            html.contains("Your own request") && html.contains("awaiting peer review"),
            "must show explanatory pill for own pending"
        );
    }

    #[test]
    fn ui_gating_detail_renders_buttons_for_others_pending() {
        let html = detail_template(false).render().expect("render");
        assert!(
            html.contains("/sessions/approvals/uuid-detail-1/approve"),
            "non-own pending detail must expose Approve form"
        );
        assert!(
            html.contains("/sessions/approvals/uuid-detail-1/reject"),
            "non-own pending detail must expose Reject form"
        );
    }

    // ---- Decision section tests ----

    #[test]
    fn decision_section_hidden_when_no_decision() {
        let tpl = detail_template(false);
        let html = tpl.render().expect("render");
        assert!(
            !html.contains("Approved by"),
            "must not show Decision section when decided_by is None"
        );
        assert!(
            !html.contains("Rejected by"),
            "must not show Decision section when decided_by is None"
        );
    }

    #[test]
    fn decision_section_shows_approver() {
        let mut tpl = detail_template(false);
        tpl.approval.status = "approved".to_string();
        tpl.approval.decided_by = Some("admin_alice".to_string());
        tpl.approval.decided_at = Some("Apr 25, 2026 22:30".to_string());
        tpl.approval.decision_reason = None;
        let html = tpl.render().expect("render");
        assert!(
            html.contains("Approved by"),
            "approved session must show 'Approved by' label"
        );
        assert!(
            html.contains("admin_alice"),
            "approver username must appear in Decision section"
        );
        assert!(
            html.contains("Apr 25, 2026 22:30"),
            "approval timestamp must appear in Decision section"
        );
    }

    #[test]
    fn decision_section_shows_rejector_with_reason() {
        let mut tpl = detail_template(false);
        tpl.approval.status = "rejected".to_string();
        tpl.approval.decided_by = Some("admin_bob".to_string());
        tpl.approval.decided_at = Some("Apr 25, 2026 23:00".to_string());
        tpl.approval.decision_reason = Some("Insufficient justification".to_string());
        let html = tpl.render().expect("render");
        assert!(
            html.contains("Rejected by"),
            "rejected session must show 'Rejected by' label"
        );
        assert!(
            html.contains("admin_bob"),
            "rejector username must appear in Decision section"
        );
        assert!(
            html.contains("Insufficient justification"),
            "decision reason must appear when present"
        );
    }

    #[test]
    fn decision_section_omits_reason_when_absent() {
        let mut tpl = detail_template(false);
        tpl.approval.status = "approved".to_string();
        tpl.approval.decided_by = Some("admin_carol".to_string());
        tpl.approval.decided_at = Some("Apr 25, 2026 22:45".to_string());
        tpl.approval.decision_reason = None;
        let html = tpl.render().expect("render");
        assert!(html.contains("admin_carol"), "approver must appear");
        assert!(
            !html.contains("Reason"),
            "Reason label must be absent when decision_reason is None"
        );
    }

    #[test]
    fn reject_form_contains_reason_textarea() {
        let html = detail_template(false).render().expect("render");
        assert!(
            html.contains(r#"name="reason"#),
            "reject form must include a textarea with name='reason'"
        );
        assert!(
            html.contains("Reject Request"),
            "reject modal must have a title"
        );
        assert!(
            html.contains("Confirm Rejection"),
            "reject modal must have a confirmation button"
        );
    }

    #[test]
    fn reject_form_hidden_for_own_pending() {
        let html = detail_template(true).render().expect("render");
        assert!(
            !html.contains(r#"name="reason"#),
            "own pending detail must NOT show the reject reason textarea"
        );
    }

    #[test]
    fn test_approval_detail_template_renders() {
        use crate::templates::base::{UserContext, VaubanConfig};

        let template = ApprovalDetailTemplate {
            title: "Approval Detail".to_string(),
            user: Some(UserContext {
                uuid: "test".to_string(),
                username: "testuser".to_string(),
                display_name: "Test User".to_string(),
                is_superuser: false,
                is_staff: false,
            }),
            vauban: VaubanConfig {
                brand_name: "VAUBAN".to_string(),
                brand_logo: None,
                theme: "dark".to_string(),
                ..Default::default()
            },
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
            approval: create_test_approval_detail("pending"),
        };

        let result = template.render();
        assert!(result.is_ok(), "ApprovalDetailTemplate should render");
    }
}
