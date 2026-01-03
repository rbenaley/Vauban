/// VAUBAN Web - Session list template.

use askama::Template;
use crate::templates::base::{UserContext, VaubanConfig, FlashMessage};

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
    pub sidebar_content: Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub sessions: Vec<SessionListItem>,
    pub status_filter: Option<String>,
    pub type_filter: Option<String>,
    pub asset_filter: Option<String>,
}
