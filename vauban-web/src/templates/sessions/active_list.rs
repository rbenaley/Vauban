/// VAUBAN Web - Active sessions list template.

use askama::Template;
use crate::templates::base::{UserContext, VaubanConfig, FlashMessage};

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
    pub sidebar_content: Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub sessions: Vec<ActiveSessionItem>,
}
