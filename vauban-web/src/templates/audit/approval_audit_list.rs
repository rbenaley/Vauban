//! Read-only admin page rendering the append-only
//! `approval_audit_log` table with pagination and filters.

use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};
use askama::Template;

/// One audit-log row, snapshot-frozen at decision time. Username
/// fields are kept as plain strings so a later user soft-deletion
/// or rename does NOT rewrite history.
#[derive(Debug, Clone)]
pub struct ApprovalAuditRow {
    pub id: i64,
    pub session_uuid: String,
    pub decision: String,
    pub actor_username: String,
    pub requester_username: String,
    pub asset_uuid: String,
    pub asset_name: String,
    pub protocol: Option<String>,
    pub duration_override_seconds: Option<i32>,
    pub decision_reason: Option<String>,
    pub decision_ip: Option<String>,
    pub decision_user_agent: Option<String>,
    pub request_id: Option<String>,
    pub created_at: String,
}

impl ApprovalAuditRow {
    /// Tailwind class for the decision badge.
    pub fn decision_class(&self) -> &'static str {
        match self.decision.as_str() {
            "approve" => "bg-green-100 text-green-800 dark:bg-green-900/50 dark:text-green-300",
            "reject" => "bg-red-100 text-red-800 dark:bg-red-900/50 dark:text-red-300",
            _ => "bg-gray-100 text-gray-800 dark:bg-gray-900/50 dark:text-gray-300",
        }
    }

    /// Human duration display ("2h", "30min", "Unlimited").
    pub fn duration_display(&self) -> String {
        crate::utils::duration_display(self.duration_override_seconds)
    }
}

#[derive(Debug, Clone)]
pub struct AuditPagination {
    pub current_page: i32,
    pub total_pages: i32,
    pub total_items: i64,
    pub has_previous: bool,
    pub has_next: bool,
}

/// Active filters; echoed back into the form so the user keeps
/// their selection across paginations.
#[derive(Debug, Clone, Default)]
pub struct ApprovalAuditFilters {
    pub actor: Option<String>,
    pub requester: Option<String>,
    pub asset: Option<String>,
    pub decision: Option<String>,
    pub from_date: Option<String>,
    pub to_date: Option<String>,
}

#[derive(Template)]
#[template(path = "audit/approval_audit_list.html")]
pub struct ApprovalAuditListTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<UserContext>,
    pub rows: Vec<ApprovalAuditRow>,
    pub pagination: AuditPagination,
    pub filters: ApprovalAuditFilters,
    /// `(value, label)` couples of the decision filter select, derived
    /// from `status_vocab::AUDIT_DECISIONS` (single source of truth,
    /// kept in lock-step with the `approval_audit_log.decision` CHECK).
    pub decisions: Vec<(String, String)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(decision: &str) -> ApprovalAuditRow {
        ApprovalAuditRow {
            id: 1,
            session_uuid: "11111111-1111-1111-1111-111111111111".to_string(),
            decision: decision.to_string(),
            actor_username: "alice".to_string(),
            requester_username: "bob".to_string(),
            asset_uuid: "22222222-2222-2222-2222-222222222222".to_string(),
            asset_name: "prod-db".to_string(),
            protocol: Some("ssh".to_string()),
            duration_override_seconds: Some(7200),
            decision_reason: Some("Maintenance window".to_string()),
            decision_ip: Some("10.0.0.5".to_string()),
            decision_user_agent: Some("Mozilla".to_string()),
            request_id: Some("abc12345".to_string()),
            created_at: "2026-04-25T10:00:00Z".to_string(),
        }
    }

    #[test]
    fn approve_class_is_green() {
        assert!(row("approve").decision_class().contains("green"));
    }

    #[test]
    fn reject_class_is_red() {
        assert!(row("reject").decision_class().contains("red"));
    }

    #[test]
    fn unknown_class_is_gray() {
        assert!(row("hijack").decision_class().contains("gray"));
    }

    #[test]
    fn duration_display_uses_shared_helper() {
        let mut r = row("approve");
        r.duration_override_seconds = Some(7200);
        assert_eq!(r.duration_display(), "2h");
        r.duration_override_seconds = None;
        assert_eq!(r.duration_display(), "Unlimited");
    }
}
