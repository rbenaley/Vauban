use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};
/// VAUBAN Web - Approval list template.
use askama::Template;

/// Approval item for list display.
#[derive(Debug, Clone)]
pub struct ApprovalListItem {
    pub uuid: String,
    pub username: String,
    pub asset_name: String,
    pub asset_type: String,
    pub session_type: String,
    pub justification: Option<String>,
    pub client_ip: String,
    pub created_at: String,
    pub status: String,
}

impl ApprovalListItem {
    /// Get status badge class.
    pub fn status_class(&self) -> &str {
        match self.status.as_str() {
            "pending" => "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/50 dark:text-yellow-300",
            "approved" => "bg-green-100 text-green-800 dark:bg-green-900/50 dark:text-green-300",
            "rejected" => "bg-red-100 text-red-800 dark:bg-red-900/50 dark:text-red-300",
            "expired" => "bg-gray-100 text-gray-800 dark:bg-gray-900/50 dark:text-gray-300",
            "orphaned" => "bg-gray-100 text-gray-800 dark:bg-gray-900/50 dark:text-gray-300",
            _ => "bg-gray-100 text-gray-800 dark:bg-gray-900/50 dark:text-gray-300",
        }
    }

    /// Get session type icon.
    pub fn session_icon(&self) -> &str {
        match self.session_type.as_str() {
            "ssh" => {
                "M8 9a3 3 0 100-6 3 3 0 000 6zM8 11a6 6 0 016 6H2a6 6 0 016-6zM16 7a1 1 0 10-2 0v1h-1a1 1 0 100 2h1v1a1 1 0 102 0v-1h1a1 1 0 100-2h-1V7z"
            }
            "rdp" => {
                "M3 4a1 1 0 011-1h12a1 1 0 011 1v2a1 1 0 01-1 1H4a1 1 0 01-1-1V4zM3 10a1 1 0 011-1h6a1 1 0 011 1v6a1 1 0 01-1 1H4a1 1 0 01-1-1v-6zM14 9a1 1 0 00-1 1v6a1 1 0 001 1h2a1 1 0 001-1v-6a1 1 0 00-1-1h-2z"
            }
            "vnc" => {
                "M9.504 1.132a1 1 0 01.992 0l1.75 1a1 1 0 11-.992 1.736L10 3.152l-1.254.716a1 1 0 11-.992-1.736l1.75-1zM5.618 4.504a1 1 0 01-.372 1.364L5.016 6l.23.132a1 1 0 11-.992 1.736L4 7.723V8a1 1 0 01-2 0V6a.996.996 0 01.52-.878l1.734-.99a1 1 0 011.364.372zm8.764 0a1 1 0 011.364-.372l1.733.99A1.002 1.002 0 0118 6v2a1 1 0 11-2 0v-.277l-.254.145a1 1 0 11-.992-1.736l.23-.132-.23-.132a1 1 0 01-.372-1.364zm-7 4a1 1 0 011.364-.372L10 8.848l1.254-.716a1 1 0 11.992 1.736L11 10.58V12a1 1 0 11-2 0v-1.42l-1.246-.712a1 1 0 01-.372-1.364zM3 11a1 1 0 011 1v1.42l1.246.712a1 1 0 11-.992 1.736l-1.75-1A1 1 0 012 14v-2a1 1 0 011-1zm14 0a1 1 0 011 1v2a1 1 0 01-.504.868l-1.75 1a1 1 0 11-.992-1.736L16 13.42V12a1 1 0 011-1zm-9.618 5.504a1 1 0 011.364-.372l.254.145V16a1 1 0 112 0v.277l.254-.145a1 1 0 11.992 1.736l-1.735.992a.995.995 0 01-1.022 0l-1.735-.992a1 1 0 01-.372-1.364z"
            }
            _ => {
                "M10 18a8 8 0 100-16 8 8 0 000 16zM9.555 7.168A1 1 0 008 8v4a1 1 0 001.555.832l3-2a1 1 0 000-1.664l-3-2z"
            }
        }
    }
}

/// Pagination data.
#[derive(Debug, Clone)]
pub struct Pagination {
    pub current_page: i32,
    pub total_pages: i32,
    pub total_items: i32,
    pub has_previous: bool,
    pub has_next: bool,
}

#[derive(Template)]
#[template(path = "sessions/approval_list.html")]
pub struct ApprovalListTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub approvals: Vec<ApprovalListItem>,
    pub pagination: Option<Pagination>,
    pub status_filter: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_approval_item(status: &str, session_type: &str) -> ApprovalListItem {
        ApprovalListItem {
            uuid: "test-uuid-123".to_string(),
            username: "testuser".to_string(),
            asset_name: "Test Server".to_string(),
            asset_type: "linux".to_string(),
            session_type: session_type.to_string(),
            justification: Some("Need access for maintenance".to_string()),
            client_ip: "192.168.1.100".to_string(),
            created_at: "2026-01-03 10:00:00".to_string(),
            status: status.to_string(),
        }
    }

    // Tests for status_class()
    #[test]
    fn test_status_class_pending() {
        let item = create_test_approval_item("pending", "ssh");
        assert!(item.status_class().contains("yellow"));
    }

    #[test]
    fn test_status_class_approved() {
        let item = create_test_approval_item("approved", "ssh");
        assert!(item.status_class().contains("green"));
    }

    #[test]
    fn test_status_class_rejected() {
        let item = create_test_approval_item("rejected", "ssh");
        assert!(item.status_class().contains("red"));
    }

    #[test]
    fn test_status_class_expired() {
        let item = create_test_approval_item("expired", "ssh");
        assert!(item.status_class().contains("gray"));
    }

    #[test]
    fn test_status_class_orphaned() {
        let item = create_test_approval_item("orphaned", "ssh");
        assert!(item.status_class().contains("gray"));
    }

    #[test]
    fn test_status_class_unknown() {
        let item = create_test_approval_item("unknown_status", "ssh");
        assert!(item.status_class().contains("gray"));
    }

    // Tests for session_icon()
    #[test]
    fn test_session_icon_ssh() {
        let item = create_test_approval_item("pending", "ssh");
        let icon = item.session_icon();
        assert!(!icon.is_empty());
        assert!(icon.contains("M8 9a3"));
    }

    #[test]
    fn test_session_icon_rdp() {
        let item = create_test_approval_item("pending", "rdp");
        let icon = item.session_icon();
        assert!(!icon.is_empty());
        assert!(icon.contains("M3 4a1"));
    }

    #[test]
    fn test_session_icon_vnc() {
        let item = create_test_approval_item("pending", "vnc");
        let icon = item.session_icon();
        assert!(!icon.is_empty());
        assert!(icon.contains("M9.504"));
    }

    #[test]
    fn test_session_icon_unknown() {
        let item = create_test_approval_item("pending", "telnet");
        let icon = item.session_icon();
        assert!(!icon.is_empty());
        assert!(icon.contains("M10 18a8"));
    }

    // Tests for ApprovalListItem struct
    #[test]
    fn test_approval_list_item_creation() {
        let item = create_test_approval_item("pending", "ssh");
        assert_eq!(item.uuid, "test-uuid-123");
        assert_eq!(item.username, "testuser");
        assert_eq!(item.asset_name, "Test Server");
        assert!(item.justification.is_some());
    }

    #[test]
    fn test_approval_list_item_without_justification() {
        let mut item = create_test_approval_item("pending", "ssh");
        item.justification = None;
        assert!(item.justification.is_none());
    }

    #[test]
    fn test_approval_list_item_clone() {
        let item = create_test_approval_item("approved", "rdp");
        let cloned = item.clone();
        assert_eq!(item.uuid, cloned.uuid);
        assert_eq!(item.status, cloned.status);
    }

    // Tests for Pagination struct
    #[test]
    fn test_pagination_creation() {
        let pagination = Pagination {
            current_page: 1,
            total_pages: 5,
            total_items: 50,
            has_previous: false,
            has_next: true,
        };
        assert_eq!(pagination.current_page, 1);
        assert_eq!(pagination.total_pages, 5);
        assert!(!pagination.has_previous);
        assert!(pagination.has_next);
    }

    #[test]
    fn test_pagination_first_page() {
        let pagination = Pagination {
            current_page: 1,
            total_pages: 10,
            total_items: 100,
            has_previous: false,
            has_next: true,
        };
        assert!(!pagination.has_previous);
        assert!(pagination.has_next);
    }

    #[test]
    fn test_pagination_last_page() {
        let pagination = Pagination {
            current_page: 10,
            total_pages: 10,
            total_items: 100,
            has_previous: true,
            has_next: false,
        };
        assert!(pagination.has_previous);
        assert!(!pagination.has_next);
    }

    #[test]
    fn test_pagination_middle_page() {
        let pagination = Pagination {
            current_page: 5,
            total_pages: 10,
            total_items: 100,
            has_previous: true,
            has_next: true,
        };
        assert!(pagination.has_previous);
        assert!(pagination.has_next);
    }

    #[test]
    fn test_pagination_single_page() {
        let pagination = Pagination {
            current_page: 1,
            total_pages: 1,
            total_items: 5,
            has_previous: false,
            has_next: false,
        };
        assert!(!pagination.has_previous);
        assert!(!pagination.has_next);
    }

    #[test]
    fn test_pagination_clone() {
        let pagination = Pagination {
            current_page: 3,
            total_pages: 10,
            total_items: 100,
            has_previous: true,
            has_next: true,
        };
        let cloned = pagination.clone();
        assert_eq!(pagination.current_page, cloned.current_page);
        assert_eq!(pagination.total_pages, cloned.total_pages);
    }

    #[test]
    fn test_approval_list_template_renders() {
        use crate::templates::base::{UserContext, VaubanConfig};

        let template = ApprovalListTemplate {
            title: "Approvals".to_string(),
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
            },
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
            approvals: vec![create_test_approval_item("pending", "ssh")],
            status_filter: None,
            pagination: Some(Pagination {
                current_page: 1,
                total_pages: 1,
                total_items: 1,
                has_previous: false,
                has_next: false,
            }),
        };

        let result = template.render();
        assert!(result.is_ok(), "ApprovalListTemplate should render");
    }
}
