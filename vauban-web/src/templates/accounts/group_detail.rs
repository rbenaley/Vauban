/// VAUBAN Web - Group detail template.

use askama::Template;
use crate::templates::base::{UserContext, VaubanConfig, FlashMessage};

/// Group member for display.
#[derive(Debug, Clone)]
pub struct GroupMember {
    pub uuid: String,
    pub username: String,
    pub email: String,
    pub full_name: Option<String>,
    pub is_active: bool,
}

/// Group detail data.
#[derive(Debug, Clone)]
pub struct GroupDetail {
    pub uuid: String,
    pub name: String,
    pub description: Option<String>,
    pub source: String,
    pub external_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub last_synced: Option<String>,
    pub members: Vec<GroupMember>,
}

impl GroupDetail {
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
#[template(path = "accounts/group_detail.html")]
pub struct GroupDetailTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content: Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub group: GroupDetail,
}
