/// VAUBAN Web - Group list template.

use askama::Template;
use crate::templates::base::{UserContext, VaubanConfig, FlashMessage};

/// Group item for list display.
#[derive(Debug, Clone)]
pub struct GroupListItem {
    pub uuid: String,
    pub name: String,
    pub description: Option<String>,
    pub source: String,
    pub member_count: i64,
    pub created_at: String,
}

impl GroupListItem {
    /// Get source display name.
    pub fn source_display(&self) -> &str {
        match self.source.as_str() {
            "local" => "Local",
            "ldap" => "LDAP",
            "saml" => "SAML",
            _ => &self.source,
        }
    }
}

#[derive(Template)]
#[template(path = "accounts/group_list.html")]
pub struct GroupListTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content: Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub groups: Vec<GroupListItem>,
    pub search: Option<String>,
}
