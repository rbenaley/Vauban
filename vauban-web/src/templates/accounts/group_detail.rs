use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};
/// VAUBAN Web - Group detail template.
use askama::Template;

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
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub group: GroupDetail,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_group_member() -> GroupMember {
        GroupMember {
            uuid: "member-uuid".to_string(),
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            full_name: Some("Test User".to_string()),
            is_active: true,
        }
    }

    fn create_test_group_detail(source: &str) -> GroupDetail {
        GroupDetail {
            uuid: "group-uuid".to_string(),
            name: "Test Group".to_string(),
            description: Some("A test group".to_string()),
            source: source.to_string(),
            external_id: None,
            created_at: "2026-01-01 00:00:00".to_string(),
            updated_at: "2026-01-02 00:00:00".to_string(),
            last_synced: None,
            members: vec![create_test_group_member()],
        }
    }

    // Tests for GroupMember
    #[test]
    fn test_group_member_creation() {
        let member = create_test_group_member();
        assert_eq!(member.username, "testuser");
        assert!(member.is_active);
    }

    #[test]
    fn test_group_member_clone() {
        let member = create_test_group_member();
        let cloned = member.clone();
        assert_eq!(member.uuid, cloned.uuid);
    }

    // Tests for GroupDetail source_display()
    #[test]
    fn test_source_display_local() {
        let group = create_test_group_detail("local");
        assert_eq!(group.source_display(), "Local");
    }

    #[test]
    fn test_source_display_ldap() {
        let group = create_test_group_detail("ldap");
        assert_eq!(group.source_display(), "LDAP");
    }

    #[test]
    fn test_source_display_saml() {
        let group = create_test_group_detail("saml");
        assert_eq!(group.source_display(), "SAML");
    }

    #[test]
    fn test_source_display_unknown() {
        let group = create_test_group_detail("oauth");
        assert_eq!(group.source_display(), "oauth");
    }

    // Tests for GroupDetail struct
    #[test]
    fn test_group_detail_creation() {
        let group = create_test_group_detail("local");
        assert_eq!(group.name, "Test Group");
        assert_eq!(group.members.len(), 1);
    }

    #[test]
    fn test_group_detail_clone() {
        let group = create_test_group_detail("local");
        let cloned = group.clone();
        assert_eq!(group.uuid, cloned.uuid);
        assert_eq!(group.members.len(), cloned.members.len());
    }

    #[test]
    fn test_group_detail_template_renders() {
        use crate::templates::base::{VaubanConfig, UserContext};

        let template = GroupDetailTemplate {
            title: "Group Detail".to_string(),
            user: Some(UserContext {
                uuid: "test".to_string(),
                username: "testuser".to_string(),
                display_name: "Test User".to_string(),
                is_superuser: true,
                is_staff: true,
            }),
            vauban: VaubanConfig {
                brand_name: "VAUBAN".to_string(),
                brand_logo: None,
                theme: "dark".to_string(),
            },
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
            group: create_test_group_detail("local"),
        };

        let result = template.render();
        assert!(result.is_ok(), "GroupDetailTemplate should render");
    }
}
