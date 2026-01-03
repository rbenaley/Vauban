/// VAUBAN Web - Asset group edit template.

use askama::Template;
use crate::templates::base::{UserContext, VaubanConfig, FlashMessage};

/// Asset group data for editing.
#[derive(Debug, Clone)]
pub struct AssetGroupEdit {
    pub uuid: String,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub color: String,
    pub icon: String,
}

#[derive(Template)]
#[template(path = "assets/group_edit.html")]
pub struct AssetGroupEditTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content: Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub group: AssetGroupEdit,
}

