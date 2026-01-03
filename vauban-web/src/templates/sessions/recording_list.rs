/// VAUBAN Web - Recording list template.

use askama::Template;
use crate::templates::base::{UserContext, VaubanConfig, FlashMessage};

/// Recording item for list display.
#[derive(Debug, Clone)]
pub struct RecordingListItem {
    pub id: i32,
    pub session_id: i32,
    pub asset_name: String,
    pub session_type: String,
    pub credential_username: String,
    pub connected_at: Option<String>,
    pub duration_seconds: Option<i64>,
    pub recording_path: String,
    pub status: String, // "ready", "recording", "processing"
}

impl RecordingListItem {
    /// Get display name for session type.
    pub fn session_type_display(&self) -> &str {
        match self.session_type.as_str() {
            "ssh" => "SSH",
            "rdp" => "RDP",
            "vnc" => "VNC",
            _ => &self.session_type,
        }
    }

    /// Get format based on session type.
    pub fn format(&self) -> &str {
        match self.session_type.as_str() {
            "ssh" => "asciinema",
            "rdp" | "vnc" => "guacamole",
            _ => "raw",
        }
    }

    /// Get format display name.
    pub fn format_display(&self) -> &str {
        match self.session_type.as_str() {
            "ssh" => "Asciinema",
            "rdp" | "vnc" => "Guacamole",
            _ => "Raw",
        }
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
#[template(path = "sessions/recording_list.html")]
pub struct RecordingListTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content: Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub recordings: Vec<RecordingListItem>,
    pub format_filter: Option<String>,
    pub asset_filter: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_recording_item(session_type: &str, duration: Option<i64>) -> RecordingListItem {
        RecordingListItem {
            id: 1,
            session_id: 100,
            asset_name: "Test Asset".to_string(),
            session_type: session_type.to_string(),
            credential_username: "testuser".to_string(),
            connected_at: Some("2026-01-03 10:00:00".to_string()),
            duration_seconds: duration,
            recording_path: "/recordings/test.cast".to_string(),
            status: "ready".to_string(),
        }
    }

    // Tests for session_type_display()
    #[test]
    fn test_session_type_display_ssh() {
        let item = create_test_recording_item("ssh", None);
        assert_eq!(item.session_type_display(), "SSH");
    }

    #[test]
    fn test_session_type_display_rdp() {
        let item = create_test_recording_item("rdp", None);
        assert_eq!(item.session_type_display(), "RDP");
    }

    #[test]
    fn test_session_type_display_vnc() {
        let item = create_test_recording_item("vnc", None);
        assert_eq!(item.session_type_display(), "VNC");
    }

    #[test]
    fn test_session_type_display_unknown() {
        let item = create_test_recording_item("telnet", None);
        assert_eq!(item.session_type_display(), "telnet");
    }

    // Tests for format()
    #[test]
    fn test_format_ssh() {
        let item = create_test_recording_item("ssh", None);
        assert_eq!(item.format(), "asciinema");
    }

    #[test]
    fn test_format_rdp() {
        let item = create_test_recording_item("rdp", None);
        assert_eq!(item.format(), "guacamole");
    }

    #[test]
    fn test_format_vnc() {
        let item = create_test_recording_item("vnc", None);
        assert_eq!(item.format(), "guacamole");
    }

    #[test]
    fn test_format_unknown() {
        let item = create_test_recording_item("telnet", None);
        assert_eq!(item.format(), "raw");
    }

    // Tests for format_display()
    #[test]
    fn test_format_display_ssh() {
        let item = create_test_recording_item("ssh", None);
        assert_eq!(item.format_display(), "Asciinema");
    }

    #[test]
    fn test_format_display_rdp() {
        let item = create_test_recording_item("rdp", None);
        assert_eq!(item.format_display(), "Guacamole");
    }

    #[test]
    fn test_format_display_vnc() {
        let item = create_test_recording_item("vnc", None);
        assert_eq!(item.format_display(), "Guacamole");
    }

    #[test]
    fn test_format_display_unknown() {
        let item = create_test_recording_item("telnet", None);
        assert_eq!(item.format_display(), "Raw");
    }

    // Tests for duration_display()
    #[test]
    fn test_duration_display_hours() {
        let item = create_test_recording_item("ssh", Some(7265)); // 2h 1m 5s
        assert_eq!(item.duration_display(), "2h 1m");
    }

    #[test]
    fn test_duration_display_minutes() {
        let item = create_test_recording_item("ssh", Some(185)); // 3m 5s
        assert_eq!(item.duration_display(), "3m 5s");
    }

    #[test]
    fn test_duration_display_seconds() {
        let item = create_test_recording_item("ssh", Some(30));
        assert_eq!(item.duration_display(), "30s");
    }

    #[test]
    fn test_duration_display_none() {
        let item = create_test_recording_item("ssh", None);
        assert_eq!(item.duration_display(), "-");
    }

    #[test]
    fn test_duration_display_zero() {
        let item = create_test_recording_item("ssh", Some(0));
        assert_eq!(item.duration_display(), "0s");
    }

    // Tests for RecordingListItem struct
    #[test]
    fn test_recording_list_item_creation() {
        let item = create_test_recording_item("ssh", Some(100));
        assert_eq!(item.id, 1);
        assert_eq!(item.session_id, 100);
        assert_eq!(item.asset_name, "Test Asset");
        assert_eq!(item.status, "ready");
    }

    #[test]
    fn test_recording_list_item_clone() {
        let item = create_test_recording_item("rdp", Some(500));
        let cloned = item.clone();
        assert_eq!(item.id, cloned.id);
        assert_eq!(item.session_type, cloned.session_type);
        assert_eq!(item.recording_path, cloned.recording_path);
    }
}
