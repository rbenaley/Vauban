/// VAUBAN Web - Session detail template.

use askama::Template;
use crate::templates::base::{UserContext, VaubanConfig, FlashMessage};

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
    pub sidebar_content: Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub session: SessionDetail,
}
