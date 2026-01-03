/// VAUBAN Web - Asset detail template.

use askama::Template;
use crate::templates::base::{UserContext, VaubanConfig, FlashMessage};

/// Asset detail data.
#[derive(Debug, Clone)]
pub struct AssetDetail {
    pub uuid: String,
    pub name: String,
    pub hostname: String,
    pub ip_address: Option<String>,
    pub port: i32,
    pub asset_type: String,
    pub status: String,
    pub group_name: Option<String>,
    pub group_uuid: Option<String>,
    pub description: Option<String>,
    pub os_type: Option<String>,
    pub os_version: Option<String>,
    pub require_mfa: bool,
    pub require_justification: bool,
    pub max_session_duration: i32,
    pub last_seen: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl AssetDetail {
    /// Get status badge class.
    pub fn status_class(&self) -> &str {
        match self.status.as_str() {
            "online" => "bg-green-100 text-green-800 dark:bg-green-900/50 dark:text-green-300",
            "offline" => "bg-red-100 text-red-800 dark:bg-red-900/50 dark:text-red-300",
            "maintenance" => "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/50 dark:text-yellow-300",
            _ => "bg-gray-100 text-gray-800 dark:bg-gray-900/50 dark:text-gray-300",
        }
    }

    /// Get asset type badge class.
    pub fn type_class(&self) -> &str {
        match self.asset_type.as_str() {
            "ssh" => "bg-green-100 text-green-800 dark:bg-green-900/50 dark:text-green-300",
            "rdp" => "bg-blue-100 text-blue-800 dark:bg-blue-900/50 dark:text-blue-300",
            "vnc" => "bg-purple-100 text-purple-800 dark:bg-purple-900/50 dark:text-purple-300",
            _ => "bg-gray-100 text-gray-800 dark:bg-gray-900/50 dark:text-gray-300",
        }
    }

    /// Format max session duration.
    pub fn max_session_display(&self) -> String {
        let hours = self.max_session_duration / 3600;
        let minutes = (self.max_session_duration % 3600) / 60;
        if hours > 0 {
            format!("{}h {}m", hours, minutes)
        } else {
            format!("{}m", minutes)
        }
    }
}

#[derive(Template)]
#[template(path = "assets/asset_detail.html")]
pub struct AssetDetailTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content: Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub asset: AssetDetail,
}
