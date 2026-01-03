/// VAUBAN Web - Asset list template.

use askama::Template;
use crate::templates::base::{UserContext, VaubanConfig, FlashMessage};

use crate::templates::accounts::user_list::Pagination;

/// Asset item for list display.
#[derive(Debug, Clone)]
pub struct AssetListItem {
    pub id: i32,
    pub name: String,
    pub hostname: String,
    pub port: i32,
    pub asset_type: String, // "ssh", "rdp", "vnc"
    pub status: String, // "online", "offline", "maintenance"
    pub group_name: Option<String>,
}

#[derive(Template)]
#[template(path = "assets/asset_list.html")]
pub struct AssetListTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content: Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub assets: Vec<AssetListItem>,
    pub pagination: Option<Pagination>,
    pub search: Option<String>,
    pub type_filter: Option<String>,
    pub status_filter: Option<String>,
    pub asset_types: Vec<(String, String)>,
    pub statuses: Vec<(String, String)>,
}

