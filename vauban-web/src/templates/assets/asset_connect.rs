/// VAUBAN Web - Asset connect template.

use askama::Template;
use crate::templates::base::{UserContext, VaubanConfig, FlashMessage};


#[derive(Template)]
#[template(path = "assets/asset_connect.html")]
pub struct AssetConnectTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content: Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
}

