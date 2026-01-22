use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};
/// VAUBAN Web - Active sessions list template.
use askama::Template;

/// Active session item for list display.
#[derive(Debug, Clone)]
pub struct ActiveSessionItem {
    pub uuid: String,
    pub username: String,
    pub asset_name: String,
    pub asset_hostname: String,
    pub session_type: String,
    pub client_ip: String,
    pub connected_at: String,
    pub duration: String,
}

impl ActiveSessionItem {
    /// Get session type badge class.
    pub fn session_type_class(&self) -> &str {
        match self.session_type.as_str() {
            "ssh" => "bg-green-100 text-green-800 dark:bg-green-900/50 dark:text-green-300",
            "rdp" => "bg-blue-100 text-blue-800 dark:bg-blue-900/50 dark:text-blue-300",
            "vnc" => "bg-purple-100 text-purple-800 dark:bg-purple-900/50 dark:text-purple-300",
            _ => "bg-gray-100 text-gray-800 dark:bg-gray-900/50 dark:text-gray-300",
        }
    }
}

#[derive(Template)]
#[template(path = "sessions/active_list.html")]
pub struct ActiveListTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub sessions: Vec<ActiveSessionItem>,
}

/// WebSocket widget for active sessions list content.
#[derive(Template)]
#[template(path = "sessions/active_list_content.html")]
pub struct ActiveListContentWidget {
    pub sessions: Vec<ActiveSessionItem>,
}

/// WebSocket widget for active sessions stats.
#[derive(Template)]
#[template(path = "sessions/active_list_stats.html")]
pub struct ActiveListStatsWidget {
    pub sessions: Vec<ActiveSessionItem>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unwrap_ok;

    fn create_test_active_session_item(session_type: &str) -> ActiveSessionItem {
        ActiveSessionItem {
            uuid: "session-uuid".to_string(),
            username: "testuser".to_string(),
            asset_name: "Test Server".to_string(),
            asset_hostname: "test.example.com".to_string(),
            session_type: session_type.to_string(),
            client_ip: "192.168.1.100".to_string(),
            connected_at: "2026-01-03 10:00:00".to_string(),
            duration: "1h 30m".to_string(),
        }
    }

    // Tests for session_type_class()
    #[test]
    fn test_session_type_class_ssh() {
        let item = create_test_active_session_item("ssh");
        assert!(item.session_type_class().contains("green"));
    }

    #[test]
    fn test_session_type_class_rdp() {
        let item = create_test_active_session_item("rdp");
        assert!(item.session_type_class().contains("blue"));
    }

    #[test]
    fn test_session_type_class_vnc() {
        let item = create_test_active_session_item("vnc");
        assert!(item.session_type_class().contains("purple"));
    }

    #[test]
    fn test_session_type_class_unknown() {
        let item = create_test_active_session_item("telnet");
        assert!(item.session_type_class().contains("gray"));
    }

    // Tests for ActiveSessionItem struct
    #[test]
    fn test_active_session_item_creation() {
        let item = create_test_active_session_item("ssh");
        assert_eq!(item.username, "testuser");
        assert_eq!(item.asset_name, "Test Server");
    }

    #[test]
    fn test_active_session_item_clone() {
        let item = create_test_active_session_item("rdp");
        let cloned = item.clone();
        assert_eq!(item.uuid, cloned.uuid);
        assert_eq!(item.duration, cloned.duration);
    }

    #[test]
    fn test_active_list_template_renders() {
        use crate::templates::base::{UserContext, VaubanConfig};

        let template = ActiveListTemplate {
            title: "Active Sessions".to_string(),
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
            sessions: vec![create_test_active_session_item("ssh")],
        };

        let result = template.render();
        assert!(result.is_ok(), "ActiveListTemplate should render");
    }

    // Tests for ActiveListContentWidget (WebSocket partial)
    #[test]
    fn test_active_list_content_widget_renders() {
        let widget = ActiveListContentWidget {
            sessions: vec![create_test_active_session_item("ssh")],
        };
        let result = widget.render();
        assert!(result.is_ok(), "ActiveListContentWidget should render");

        let html = unwrap_ok!(result);
        assert!(html.contains("testuser"));
        assert!(html.contains("Test Server"));
    }

    #[test]
    fn test_active_list_content_widget_empty() {
        let widget = ActiveListContentWidget {
            sessions: Vec::new(),
        };
        let result = widget.render();
        assert!(result.is_ok(), "ActiveListContentWidget should render empty");

        let html = unwrap_ok!(result);
        assert!(html.contains("No active sessions"));
    }

    #[test]
    fn test_active_list_content_widget_multiple_sessions() {
        let widget = ActiveListContentWidget {
            sessions: vec![
                create_test_active_session_item("ssh"),
                create_test_active_session_item("rdp"),
                create_test_active_session_item("vnc"),
            ],
        };
        let result = widget.render();
        assert!(result.is_ok());

        let html = unwrap_ok!(result);
        assert!(html.contains("SSH"));
        assert!(html.contains("RDP"));
        assert!(html.contains("VNC"));
    }

    // Tests for ActiveListStatsWidget (WebSocket partial)
    #[test]
    fn test_active_list_stats_widget_renders() {
        let widget = ActiveListStatsWidget {
            sessions: vec![create_test_active_session_item("ssh")],
        };
        let result = widget.render();
        assert!(result.is_ok(), "ActiveListStatsWidget should render");

        let html = unwrap_ok!(result);
        assert!(html.contains("Active Sessions"));
        assert!(html.contains("1")); // 1 session
    }

    #[test]
    fn test_active_list_stats_widget_empty() {
        let widget = ActiveListStatsWidget {
            sessions: Vec::new(),
        };
        let result = widget.render();
        assert!(result.is_ok(), "ActiveListStatsWidget should render with 0");

        let html = unwrap_ok!(result);
        assert!(html.contains("0"));
    }

    #[test]
    fn test_active_list_stats_widget_count() {
        let widget = ActiveListStatsWidget {
            sessions: vec![
                create_test_active_session_item("ssh"),
                create_test_active_session_item("rdp"),
                create_test_active_session_item("vnc"),
            ],
        };
        let result = widget.render();
        assert!(result.is_ok());

        let html = unwrap_ok!(result);
        assert!(html.contains("3")); // 3 sessions
    }
}
