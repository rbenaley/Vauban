use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};
/// VAUBAN Web - Session detail template.
use askama::Template;

/// Session detail data.
#[derive(Debug, Clone)]
pub struct SessionDetail {
    pub id: i32,
    pub uuid: String,
    pub username: String,
    pub user_uuid: String,
    pub asset_name: String,
    pub asset_hostname: String,
    pub asset_uuid: String,
    pub asset_type: String,
    pub session_type: String,
    pub status: String,
    pub credential_username: String,
    pub client_ip: String,
    pub client_user_agent: Option<String>,
    pub proxy_instance: Option<String>,
    pub connected_at: Option<String>,
    pub disconnected_at: Option<String>,
    pub duration: Option<String>,
    pub justification: Option<String>,
    pub is_recorded: bool,
    pub recording_path: Option<String>,
    pub bytes_sent: i64,
    pub bytes_received: i64,
    pub commands_count: i32,
    pub created_at: String,
}

impl SessionDetail {
    /// Get status badge class.
    pub fn status_class(&self) -> &str {
        match self.status.as_str() {
            "active" => "bg-green-100 text-green-800 dark:bg-green-900/50 dark:text-green-300",
            "completed" => "bg-blue-100 text-blue-800 dark:bg-blue-900/50 dark:text-blue-300",
            "failed" => "bg-red-100 text-red-800 dark:bg-red-900/50 dark:text-red-300",
            "pending" => "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/50 dark:text-yellow-300",
            _ => "bg-gray-100 text-gray-800 dark:bg-gray-900/50 dark:text-gray-300",
        }
    }

    /// Get session type badge class.
    pub fn type_class(&self) -> &str {
        match self.session_type.as_str() {
            "ssh" => "bg-green-100 text-green-800 dark:bg-green-900/50 dark:text-green-300",
            "rdp" => "bg-blue-100 text-blue-800 dark:bg-blue-900/50 dark:text-blue-300",
            "vnc" => "bg-purple-100 text-purple-800 dark:bg-purple-900/50 dark:text-purple-300",
            _ => "bg-gray-100 text-gray-800 dark:bg-gray-900/50 dark:text-gray-300",
        }
    }

    /// Format bytes to human-readable size.
    pub fn format_bytes(bytes: i64) -> String {
        const KB: i64 = 1024;
        const MB: i64 = KB * 1024;
        const GB: i64 = MB * 1024;

        if bytes >= GB {
            format!("{:.2} GB", bytes as f64 / GB as f64)
        } else if bytes >= MB {
            format!("{:.2} MB", bytes as f64 / MB as f64)
        } else if bytes >= KB {
            format!("{:.2} KB", bytes as f64 / KB as f64)
        } else {
            format!("{} B", bytes)
        }
    }

    /// Get formatted bytes sent.
    pub fn bytes_sent_display(&self) -> String {
        Self::format_bytes(self.bytes_sent)
    }

    /// Get formatted bytes received.
    pub fn bytes_received_display(&self) -> String {
        Self::format_bytes(self.bytes_received)
    }
}

#[derive(Template)]
#[template(path = "sessions/session_detail.html")]
pub struct SessionDetailTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub session: SessionDetail,
    /// Whether to show the "Play Recording" button (only for admin users).
    pub show_play_recording: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_session_detail(status: &str, session_type: &str) -> SessionDetail {
        SessionDetail {
            id: 1,
            uuid: "session-uuid".to_string(),
            username: "testuser".to_string(),
            user_uuid: "user-uuid".to_string(),
            asset_name: "Test Server".to_string(),
            asset_hostname: "test.example.com".to_string(),
            asset_uuid: "asset-uuid".to_string(),
            asset_type: "linux".to_string(),
            session_type: session_type.to_string(),
            status: status.to_string(),
            credential_username: "admin".to_string(),
            client_ip: "192.168.1.100".to_string(),
            client_user_agent: Some("Mozilla/5.0".to_string()),
            proxy_instance: Some("proxy-01".to_string()),
            connected_at: Some("2026-01-03 10:00:00".to_string()),
            disconnected_at: Some("2026-01-03 11:00:00".to_string()),
            duration: Some("1h 0m".to_string()),
            justification: Some("Maintenance".to_string()),
            is_recorded: true,
            recording_path: Some("/recordings/session.cast".to_string()),
            bytes_sent: 10240,
            bytes_received: 20480,
            commands_count: 50,
            created_at: "2026-01-03 09:50:00".to_string(),
        }
    }

    // Tests for status_class()
    #[test]
    fn test_status_class_active() {
        let detail = create_test_session_detail("active", "ssh");
        assert!(detail.status_class().contains("green"));
    }

    #[test]
    fn test_status_class_completed() {
        let detail = create_test_session_detail("completed", "ssh");
        assert!(detail.status_class().contains("blue"));
    }

    #[test]
    fn test_status_class_failed() {
        let detail = create_test_session_detail("failed", "ssh");
        assert!(detail.status_class().contains("red"));
    }

    #[test]
    fn test_status_class_pending() {
        let detail = create_test_session_detail("pending", "ssh");
        assert!(detail.status_class().contains("yellow"));
    }

    #[test]
    fn test_status_class_unknown() {
        let detail = create_test_session_detail("unknown", "ssh");
        assert!(detail.status_class().contains("gray"));
    }

    // Tests for type_class()
    #[test]
    fn test_type_class_ssh() {
        let detail = create_test_session_detail("active", "ssh");
        assert!(detail.type_class().contains("green"));
    }

    #[test]
    fn test_type_class_rdp() {
        let detail = create_test_session_detail("active", "rdp");
        assert!(detail.type_class().contains("blue"));
    }

    #[test]
    fn test_type_class_vnc() {
        let detail = create_test_session_detail("active", "vnc");
        assert!(detail.type_class().contains("purple"));
    }

    #[test]
    fn test_type_class_unknown() {
        let detail = create_test_session_detail("active", "telnet");
        assert!(detail.type_class().contains("gray"));
    }

    // Tests for format_bytes()
    #[test]
    fn test_format_bytes_bytes() {
        assert_eq!(SessionDetail::format_bytes(500), "500 B");
    }

    #[test]
    fn test_format_bytes_kilobytes() {
        assert_eq!(SessionDetail::format_bytes(1024), "1.00 KB");
        assert_eq!(SessionDetail::format_bytes(2048), "2.00 KB");
    }

    #[test]
    fn test_format_bytes_megabytes() {
        assert_eq!(SessionDetail::format_bytes(1048576), "1.00 MB");
        assert_eq!(SessionDetail::format_bytes(5242880), "5.00 MB");
    }

    #[test]
    fn test_format_bytes_gigabytes() {
        assert_eq!(SessionDetail::format_bytes(1073741824), "1.00 GB");
    }

    // Tests for bytes_sent_display() and bytes_received_display()
    #[test]
    fn test_bytes_sent_display() {
        let detail = create_test_session_detail("active", "ssh");
        assert_eq!(detail.bytes_sent_display(), "10.00 KB");
    }

    #[test]
    fn test_bytes_received_display() {
        let detail = create_test_session_detail("active", "ssh");
        assert_eq!(detail.bytes_received_display(), "20.00 KB");
    }

    // Tests for SessionDetail struct
    #[test]
    fn test_session_detail_creation() {
        let detail = create_test_session_detail("active", "ssh");
        assert_eq!(detail.id, 1);
        assert!(detail.is_recorded);
    }

    #[test]
    fn test_session_detail_clone() {
        let detail = create_test_session_detail("completed", "rdp");
        let cloned = detail.clone();
        assert_eq!(detail.uuid, cloned.uuid);
    }

    #[test]
    fn test_session_detail_template_renders() {
        let template = SessionDetailTemplate {
            title: "Session Detail".to_string(),
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
            session: create_test_session_detail("active", "ssh"),
            show_play_recording: true,
        };

        let result = template.render();
        assert!(result.is_ok(), "SessionDetailTemplate should render");
    }

    #[test]
    fn test_session_detail_template_renders_without_play_button() {
        let template = SessionDetailTemplate {
            title: "Session Detail".to_string(),
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
            session: create_test_session_detail("active", "ssh"),
            show_play_recording: false,
        };

        assert!(!template.show_play_recording);
        let result = template.render();
        assert!(result.is_ok(), "SessionDetailTemplate should render without play button");
    }
}
