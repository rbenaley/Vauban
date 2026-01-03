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
