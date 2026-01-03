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
