/// VAUBAN Web - Asset group detail template.

use askama::Template;
use crate::templates::base::{UserContext, VaubanConfig, FlashMessage};

/// Asset in group for display.
#[derive(Debug, Clone)]
pub struct GroupAssetItem {
    pub uuid: String,
    pub name: String,
    pub hostname: String,
    pub asset_type: String,
    pub status: String,
}

impl GroupAssetItem {
    pub fn status_class(&self) -> &str {
        match self.status.as_str() {
            "online" => "bg-green-100 text-green-800 dark:bg-green-900/50 dark:text-green-300",
            "offline" => "bg-red-100 text-red-800 dark:bg-red-900/50 dark:text-red-300",
            "maintenance" => "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/50 dark:text-yellow-300",
            _ => "bg-gray-100 text-gray-800 dark:bg-gray-900/50 dark:text-gray-300",
        }
    }
}

/// Asset group detail data.
#[derive(Debug, Clone)]
pub struct AssetGroupDetail {
    pub uuid: String,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub color: String,
    pub icon: String,
    pub created_at: String,
    pub updated_at: String,
    pub assets: Vec<GroupAssetItem>,
}

#[derive(Template)]
#[template(path = "assets/group_detail.html")]
pub struct AssetGroupDetailTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content: Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub group: AssetGroupDetail,
}
