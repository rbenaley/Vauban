/// VAUBAN Web - Approval detail template.

use askama::Template;
use crate::templates::base::{UserContext, VaubanConfig, FlashMessage};

/// Approval detail data.
#[derive(Debug, Clone)]
pub struct ApprovalDetail {
    pub uuid: String,
    pub username: String,
    pub user_email: String,
    pub asset_name: String,
    pub asset_type: String,
    pub asset_hostname: String,
    pub session_type: String,
    pub status: String,
    pub justification: Option<String>,
    pub client_ip: String,
    pub credential_username: String,
    pub created_at: String,
    pub is_recorded: bool,
}

impl ApprovalDetail {
    /// Get status badge class.
    pub fn status_class(&self) -> &str {
        match self.status.as_str() {
            "pending" => "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/50 dark:text-yellow-300",
            "approved" => "bg-green-100 text-green-800 dark:bg-green-900/50 dark:text-green-300",
            "rejected" => "bg-red-100 text-red-800 dark:bg-red-900/50 dark:text-red-300",
            "expired" => "bg-gray-100 text-gray-800 dark:bg-gray-900/50 dark:text-gray-300",
            _ => "bg-gray-100 text-gray-800 dark:bg-gray-900/50 dark:text-gray-300",
        }
    }

    /// Check if pending.
    pub fn is_pending(&self) -> bool {
        self.status == "pending"
    }
}

#[derive(Template)]
#[template(path = "sessions/approval_detail.html")]
pub struct ApprovalDetailTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content: Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub approval: ApprovalDetail,
}
