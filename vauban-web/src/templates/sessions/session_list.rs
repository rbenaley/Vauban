use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};
/// VAUBAN Web - Session list template.
use askama::Template;

/// Session item for list display.
#[derive(Debug, Clone)]
pub struct SessionListItem {
    pub id: i32,
    pub uuid: String,
    pub asset_name: String,
    pub asset_hostname: String,
    pub session_type: String,
    pub status: String,
    pub credential_username: String,
    pub connected_at: Option<String>,
    pub duration_seconds: Option<i64>,
    pub is_recorded: bool,
}

impl SessionListItem {
    /// Get display name for session type.
    pub fn session_type_display(&self) -> &str {
        match self.session_type.as_str() {
            "ssh" => "SSH",
            "rdp" => "RDP",
            "vnc" => "VNC",
            _ => &self.session_type,
        }
    }

    /// Get display name for status.
    pub fn status_display(&self) -> &str {
        match self.status.as_str() {
            "active" => "Active",
            "disconnected" => "Disconnected",
            "completed" => "Completed",
            "terminated" => "Terminated",
            "pending" => "Pending",
            "failed" => "Failed",
            _ => &self.status,
        }
    }

    /// Check if session is active.
    pub fn is_active(&self) -> bool {
        self.status == "active"
    }

    /// Format duration for display.
    pub fn duration_display(&self) -> String {
        match self.duration_seconds {
            Some(secs) if secs >= 3600 => format!("{}h {}m", secs / 3600, (secs % 3600) / 60),
            Some(secs) if secs >= 60 => format!("{}m {}s", secs / 60, secs % 60),
            Some(secs) => format!("{}s", secs),
            None => "-".to_string(),
        }
    }
}

#[derive(Template)]
#[template(path = "sessions/session_list.html")]
pub struct SessionListTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub sessions: Vec<SessionListItem>,
    pub status_filter: Option<String>,
    pub type_filter: Option<String>,
    pub asset_filter: Option<String>,
    /// Whether to show the "View" link (only for admin users).
    pub show_view_link: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_session_item(
        session_type: &str,
        status: &str,
        duration: Option<i64>,
    ) -> SessionListItem {
        SessionListItem {
            id: 1,
            uuid: "test-uuid".to_string(),
            asset_name: "Test Asset".to_string(),
            asset_hostname: "test.example.com".to_string(),
            session_type: session_type.to_string(),
            status: status.to_string(),
            credential_username: "testuser".to_string(),
            connected_at: Some("2026-01-03 10:00:00".to_string()),
            duration_seconds: duration,
            is_recorded: true,
        }
    }

    // Tests for session_type_display()
    #[test]
    fn test_session_type_display_ssh() {
        let item = create_test_session_item("ssh", "active", None);
        assert_eq!(item.session_type_display(), "SSH");
    }

    #[test]
    fn test_session_type_display_rdp() {
        let item = create_test_session_item("rdp", "active", None);
        assert_eq!(item.session_type_display(), "RDP");
    }

    #[test]
    fn test_session_type_display_vnc() {
        let item = create_test_session_item("vnc", "active", None);
        assert_eq!(item.session_type_display(), "VNC");
    }

    #[test]
    fn test_session_type_display_unknown() {
        let item = create_test_session_item("telnet", "active", None);
        assert_eq!(item.session_type_display(), "telnet");
    }

    // Tests for status_display()
    #[test]
    fn test_status_display_active() {
        let item = create_test_session_item("ssh", "active", None);
        assert_eq!(item.status_display(), "Active");
    }

    #[test]
    fn test_status_display_disconnected() {
        let item = create_test_session_item("ssh", "disconnected", None);
        assert_eq!(item.status_display(), "Disconnected");
    }

    #[test]
    fn test_status_display_completed() {
        let item = create_test_session_item("ssh", "completed", None);
        assert_eq!(item.status_display(), "Completed");
    }

    #[test]
    fn test_status_display_terminated() {
        let item = create_test_session_item("ssh", "terminated", None);
        assert_eq!(item.status_display(), "Terminated");
    }

    #[test]
    fn test_status_display_pending() {
        let item = create_test_session_item("ssh", "pending", None);
        assert_eq!(item.status_display(), "Pending");
    }

    #[test]
    fn test_status_display_failed() {
        let item = create_test_session_item("ssh", "failed", None);
        assert_eq!(item.status_display(), "Failed");
    }

    #[test]
    fn test_status_display_unknown() {
        let item = create_test_session_item("ssh", "unknown_status", None);
        assert_eq!(item.status_display(), "unknown_status");
    }

    // Tests for is_active()
    #[test]
    fn test_is_active_true() {
        let item = create_test_session_item("ssh", "active", None);
        assert!(item.is_active());
    }

    #[test]
    fn test_is_active_false() {
        let item = create_test_session_item("ssh", "completed", None);
        assert!(!item.is_active());
    }

    // Tests for duration_display()
    #[test]
    fn test_duration_display_hours() {
        let item = create_test_session_item("ssh", "active", Some(3661)); // 1h 1m 1s
        assert_eq!(item.duration_display(), "1h 1m");
    }

    #[test]
    fn test_duration_display_minutes() {
        let item = create_test_session_item("ssh", "active", Some(125)); // 2m 5s
        assert_eq!(item.duration_display(), "2m 5s");
    }

    #[test]
    fn test_duration_display_seconds() {
        let item = create_test_session_item("ssh", "active", Some(45));
        assert_eq!(item.duration_display(), "45s");
    }

    #[test]
    fn test_duration_display_none() {
        let item = create_test_session_item("ssh", "active", None);
        assert_eq!(item.duration_display(), "-");
    }

    #[test]
    fn test_duration_display_zero() {
        let item = create_test_session_item("ssh", "active", Some(0));
        assert_eq!(item.duration_display(), "0s");
    }

    // Tests for SessionListItem struct
    #[test]
    fn test_session_list_item_creation() {
        let item = create_test_session_item("ssh", "active", Some(100));
        assert_eq!(item.id, 1);
        assert_eq!(item.uuid, "test-uuid");
        assert_eq!(item.asset_name, "Test Asset");
        assert!(item.is_recorded);
    }

    #[test]
    fn test_session_list_item_clone() {
        let item = create_test_session_item("rdp", "completed", Some(500));
        let cloned = item.clone();
        assert_eq!(item.id, cloned.id);
        assert_eq!(item.session_type, cloned.session_type);
    }

    #[test]
    fn test_session_list_template_renders() {
        use crate::templates::base::{UserContext, VaubanConfig};

        let template = SessionListTemplate {
            title: "Sessions".to_string(),
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
            sessions: vec![create_test_session_item("ssh", "active", Some(100))],
            status_filter: None,
            type_filter: None,
            asset_filter: None,
            show_view_link: true,
        };

        let result = template.render();
        assert!(result.is_ok(), "SessionListTemplate should render");
    }

    #[test]
    fn test_session_list_template_renders_empty() {
        use crate::templates::base::{UserContext, VaubanConfig};

        let template = SessionListTemplate {
            title: "Sessions".to_string(),
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
            sessions: Vec::new(),
            status_filter: None,
            type_filter: None,
            asset_filter: None,
            show_view_link: false,
        };

        let result = template.render();
        assert!(result.is_ok(), "Empty SessionListTemplate should render");
    }

    #[test]
    fn test_session_list_show_view_link_admin() {
        use crate::templates::base::{UserContext, VaubanConfig};

        let template = SessionListTemplate {
            title: "Sessions".to_string(),
            user: Some(UserContext {
                uuid: "admin".to_string(),
                username: "admin".to_string(),
                display_name: "Admin User".to_string(),
                is_superuser: true,
                is_staff: true,
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
            sessions: vec![create_test_session_item("ssh", "active", Some(100))],
            status_filter: None,
            type_filter: None,
            asset_filter: None,
            show_view_link: true,
        };

        assert!(template.show_view_link);
        let result = template.render();
        assert!(result.is_ok());
    }

    #[test]
    fn test_session_list_hide_view_link_normal_user() {
        use crate::templates::base::{UserContext, VaubanConfig};

        let template = SessionListTemplate {
            title: "Sessions".to_string(),
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
            sessions: vec![create_test_session_item("ssh", "active", Some(100))],
            status_filter: None,
            type_filter: None,
            asset_filter: None,
            show_view_link: false,
        };

        assert!(!template.show_view_link);
        let result = template.render();
        assert!(result.is_ok());
    }
}
