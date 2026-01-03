/// VAUBAN Web - Dashboard home template.

use askama::Template;
use crate::templates::base::{BaseTemplate, UserContext, VaubanConfig, FlashMessage};


/// Favorite asset for dashboard.
#[derive(Debug, Clone)]
pub struct FavoriteAsset {
    pub id: i32,
    pub name: String,
    pub hostname: String,
    pub asset_type: String, // "ssh", "rdp", "vnc"
}

#[derive(Template)]
#[template(path = "dashboard/home.html")]
pub struct HomeTemplate {
    // Base template fields
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content: Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    // Page-specific fields
    pub favorite_assets: Vec<FavoriteAsset>,
}

