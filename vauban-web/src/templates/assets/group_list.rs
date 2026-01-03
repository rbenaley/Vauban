/// VAUBAN Web - Asset group list template.

use askama::Template;
use crate::templates::base::{UserContext, VaubanConfig, FlashMessage};

/// Asset group item for list display.
#[derive(Debug, Clone)]
pub struct AssetGroupItem {
    pub uuid: String,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub color: String,
    pub icon: String,
    pub asset_count: i64,
    pub created_at: String,
}

#[derive(Template)]
#[template(path = "assets/group_list.html")]
pub struct AssetGroupListTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content: Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub groups: Vec<AssetGroupItem>,
    pub search: Option<String>,
}
