/// VAUBAN Web - Recording play template.

use askama::Template;
use crate::templates::base::{UserContext, VaubanConfig, FlashMessage};

/// Recording data for player.
#[derive(Debug, Clone)]
pub struct RecordingData {
    pub session_id: i32,
    pub session_uuid: String,
    pub username: String,
    pub asset_name: String,
    pub asset_hostname: String,
    pub session_type: String,
    pub connected_at: Option<String>,
    pub disconnected_at: Option<String>,
    pub duration: Option<String>,
    pub recording_path: Option<String>,
    pub bytes_sent: i64,
    pub bytes_received: i64,
    pub commands_count: i32,
}

impl RecordingData {
    /// Get session type badge class.
    pub fn type_class(&self) -> &str {
        match self.session_type.as_str() {
            "ssh" => "bg-green-100 text-green-800 dark:bg-green-900/50 dark:text-green-300",
            "rdp" => "bg-blue-100 text-blue-800 dark:bg-blue-900/50 dark:text-blue-300",
            "vnc" => "bg-purple-100 text-purple-800 dark:bg-purple-900/50 dark:text-purple-300",
            _ => "bg-gray-100 text-gray-800 dark:bg-gray-900/50 dark:text-gray-300",
        }
    }

    /// Check if this is an SSH session (terminal replay).
    pub fn is_ssh(&self) -> bool {
        self.session_type == "ssh"
    }

    /// Check if this is an RDP/VNC session (video replay).
    pub fn is_graphical(&self) -> bool {
        self.session_type == "rdp" || self.session_type == "vnc"
    }
}

#[derive(Template)]
#[template(path = "sessions/recording_play.html")]
pub struct RecordingPlayTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content: Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub recording: RecordingData,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_recording_data(session_type: &str) -> RecordingData {
        RecordingData {
            session_id: 1,
            session_uuid: "session-uuid".to_string(),
            username: "testuser".to_string(),
            asset_name: "Test Server".to_string(),
            asset_hostname: "test.example.com".to_string(),
            session_type: session_type.to_string(),
            connected_at: Some("2026-01-03 10:00:00".to_string()),
            disconnected_at: Some("2026-01-03 11:00:00".to_string()),
            duration: Some("1h 0m".to_string()),
            recording_path: Some("/recordings/session.cast".to_string()),
            bytes_sent: 10240,
            bytes_received: 20480,
            commands_count: 50,
        }
    }

    // Tests for type_class()
    #[test]
    fn test_type_class_ssh() {
        let data = create_test_recording_data("ssh");
        assert!(data.type_class().contains("green"));
    }

    #[test]
    fn test_type_class_rdp() {
        let data = create_test_recording_data("rdp");
        assert!(data.type_class().contains("blue"));
    }

    #[test]
    fn test_type_class_vnc() {
        let data = create_test_recording_data("vnc");
        assert!(data.type_class().contains("purple"));
    }

    #[test]
    fn test_type_class_unknown() {
        let data = create_test_recording_data("telnet");
        assert!(data.type_class().contains("gray"));
    }

    // Tests for is_ssh()
    #[test]
    fn test_is_ssh_true() {
        let data = create_test_recording_data("ssh");
        assert!(data.is_ssh());
    }

    #[test]
    fn test_is_ssh_false() {
        let data = create_test_recording_data("rdp");
        assert!(!data.is_ssh());
    }

    // Tests for is_graphical()
    #[test]
    fn test_is_graphical_rdp() {
        let data = create_test_recording_data("rdp");
        assert!(data.is_graphical());
    }

    #[test]
    fn test_is_graphical_vnc() {
        let data = create_test_recording_data("vnc");
        assert!(data.is_graphical());
    }

    #[test]
    fn test_is_graphical_ssh() {
        let data = create_test_recording_data("ssh");
        assert!(!data.is_graphical());
    }

    // Tests for RecordingData struct
    #[test]
    fn test_recording_data_creation() {
        let data = create_test_recording_data("ssh");
        assert_eq!(data.session_id, 1);
        assert_eq!(data.commands_count, 50);
    }

    #[test]
    fn test_recording_data_clone() {
        let data = create_test_recording_data("rdp");
        let cloned = data.clone();
        assert_eq!(data.session_uuid, cloned.session_uuid);
        assert_eq!(data.bytes_sent, cloned.bytes_sent);
    }
}
