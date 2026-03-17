use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};
/// VAUBAN Web - Recording play template.
use askama::Template;

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

    /// Check if this recording uses segmented format (directory-based, DASH playback).
    /// New recordings end with `/` (directory), legacy ones end with `.mp4`.
    pub fn is_segmented(&self) -> bool {
        self.recording_path
            .as_deref()
            .is_some_and(|p| p.ends_with('/'))
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
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
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

    #[test]
    fn test_recording_play_template_renders() {
        use crate::templates::base::{UserContext, VaubanConfig};

        let template = RecordingPlayTemplate {
            title: "Recording".to_string(),
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
            recording: create_test_recording_data("ssh"),
        };

        let result = template.render();
        assert!(result.is_ok(), "RecordingPlayTemplate should render");
    }

    #[test]
    fn test_is_segmented_directory_path() {
        let mut data = create_test_recording_data("rdp");
        data.recording_path = Some("/recordings/2026/03/uuid-123/".to_string());
        assert!(data.is_segmented());
    }

    #[test]
    fn test_is_segmented_legacy_mp4() {
        let mut data = create_test_recording_data("rdp");
        data.recording_path = Some("/recordings/2026/03/uuid-123.mp4".to_string());
        assert!(!data.is_segmented());
    }

    #[test]
    fn test_is_segmented_none() {
        let mut data = create_test_recording_data("rdp");
        data.recording_path = None;
        assert!(!data.is_segmented());
    }

    #[test]
    fn test_legacy_recording_renders_native_video() {
        use crate::templates::base::{UserContext, VaubanConfig};

        let mut rec = create_test_recording_data("rdp");
        rec.recording_path = Some("/recordings/2026/03/uuid.mp4".to_string());

        let template = RecordingPlayTemplate {
            title: "Recording".to_string(),
            user: Some(UserContext {
                uuid: "admin".to_string(),
                username: "admin".to_string(),
                display_name: "Admin".to_string(),
                is_superuser: true,
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
            recording: rec,
        };

        let html = template.render().unwrap();
        assert!(
            html.contains("<source src=\"/recordings/"),
            "legacy should use <source>"
        );
        assert!(
            !html.contains("shaka-player"),
            "legacy should not load shaka"
        );
    }

    #[test]
    fn test_segmented_recording_renders_shaka_player() {
        use crate::templates::base::{UserContext, VaubanConfig};

        let mut rec = create_test_recording_data("rdp");
        rec.recording_path = Some("/recordings/2026/03/uuid-seg/".to_string());

        let template = RecordingPlayTemplate {
            title: "Recording".to_string(),
            user: Some(UserContext {
                uuid: "admin".to_string(),
                username: "admin".to_string(),
                display_name: "Admin".to_string(),
                is_superuser: true,
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
            recording: rec,
        };

        let html = template.render().unwrap();
        assert!(
            html.contains("shaka-player.compiled.js"),
            "segmented should load shaka"
        );
        assert!(
            html.contains("shaka-init.js"),
            "segmented should load shaka init script"
        );
        assert!(
            html.contains("data-manifest=\"/recordings/"),
            "segmented should have data-manifest attr"
        );
        assert!(
            html.contains("/manifest.mpd"),
            "segmented should reference MPD manifest"
        );
        assert!(
            !html.contains("<source src=\"/recordings/"),
            "segmented should not use <source>"
        );
    }

    #[test]
    fn test_ssh_recording_renders_asciinema_player() {
        use crate::templates::base::{UserContext, VaubanConfig};

        let rec = create_test_recording_data("ssh");

        let template = RecordingPlayTemplate {
            title: "Recording".to_string(),
            user: Some(UserContext {
                uuid: "admin".to_string(),
                username: "admin".to_string(),
                display_name: "Admin".to_string(),
                is_superuser: true,
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
            recording: rec,
        };

        let html = template.render().unwrap();
        assert!(
            html.contains("asciinema-player.min.js"),
            "SSH should load asciinema player JS"
        );
        assert!(
            html.contains("asciinema-init.js"),
            "SSH should load asciinema init script"
        );
        assert!(
            html.contains("asciinema-player.css"),
            "SSH should load asciinema player CSS"
        );
        assert!(
            html.contains("data-src=\"/recordings/session-uuid/session.cast\""),
            "SSH should have data-src pointing to session.cast"
        );
        assert!(
            !html.contains("shaka-player"),
            "SSH should not load video player"
        );
        assert!(
            !html.contains("<video"),
            "SSH should not use <video> element"
        );
    }

    #[test]
    fn test_ssh_recording_unavailable_renders_fallback() {
        use crate::templates::base::{UserContext, VaubanConfig};

        let mut rec = create_test_recording_data("ssh");
        rec.recording_path = None;

        let template = RecordingPlayTemplate {
            title: "Recording".to_string(),
            user: Some(UserContext {
                uuid: "admin".to_string(),
                username: "admin".to_string(),
                display_name: "Admin".to_string(),
                is_superuser: true,
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
            recording: rec,
        };

        let html = template.render().unwrap();
        assert!(
            html.contains("SSH Recording not available"),
            "unavailable SSH should show fallback message"
        );
        assert!(
            !html.contains("asciinema-player.min.js"),
            "unavailable SSH should not load player"
        );
        assert!(
            !html.contains("data-src="),
            "unavailable SSH should not have data-src"
        );
    }
}
