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

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_group_item(source: &str) -> GroupListItem {
        GroupListItem {
            uuid: "group-uuid".to_string(),
            name: "Test Group".to_string(),
            description: Some("A test group".to_string()),
            source: source.to_string(),
            member_count: 5,
            created_at: "2026-01-01 00:00:00".to_string(),
        }
    }

    // Tests for source_display()
    #[test]
    fn test_source_display_local() {
        let item = create_test_group_item("local");
        assert_eq!(item.source_display(), "Local");
    }

    #[test]
    fn test_source_display_ldap() {
        let item = create_test_group_item("ldap");
        assert_eq!(item.source_display(), "LDAP");
    }

    #[test]
    fn test_source_display_saml() {
        let item = create_test_group_item("saml");
        assert_eq!(item.source_display(), "SAML");
    }

    #[test]
    fn test_source_display_unknown() {
        let item = create_test_group_item("oidc");
        assert_eq!(item.source_display(), "oidc");
    }

    // Tests for GroupListItem struct
    #[test]
    fn test_group_list_item_creation() {
        let item = create_test_group_item("local");
        assert_eq!(item.name, "Test Group");
        assert_eq!(item.member_count, 5);
    }

    #[test]
    fn test_group_list_item_without_description() {
        let mut item = create_test_group_item("local");
        item.description = None;
        assert!(item.description.is_none());
    }

    #[test]
    fn test_group_list_item_clone() {
        let item = create_test_group_item("ldap");
        let cloned = item.clone();
        assert_eq!(item.uuid, cloned.uuid);
        assert_eq!(item.member_count, cloned.member_count);
    }
}
