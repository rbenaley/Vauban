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
}

impl ApprovalDetail {
    /// Get status badge class.
    pub fn status_class(&self) -> &str {
        match self.status.as_str() {
            "pending" => "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/50 dark:text-yellow-300",
            "approved" => "bg-green-100 text-green-800 dark:bg-green-900/50 dark:text-green-300",
            "rejected" => "bg-red-100 text-red-800 dark:bg-red-900/50 dark:text-red-300",
            "expired" => "bg-gray-100 text-gray-800 dark:bg-gray-900/50 dark:text-gray-300",
            _ => "bg-gray-100 text-gray-800 dark:bg-gray-900/50 dark:text-gray-300",
        }
    }

    /// Check if pending.
    pub fn is_pending(&self) -> bool {
        self.status == "pending"
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
}
