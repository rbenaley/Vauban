/// VAUBAN Web - Group add member template.
use askama::Template;

use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};

/// Basic group info for add member page.
#[derive(Debug, Clone)]
pub struct GroupInfo {
    pub uuid: String,
    pub name: String,
}

/// Available user to add to group.
#[derive(Debug, Clone)]
pub struct AvailableUser {
    pub uuid: String,
    pub username: String,
    pub email: String,
}

#[derive(Template)]
#[template(path = "accounts/group_add_member.html")]
pub struct GroupAddMemberTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub group: GroupInfo,
    pub available_users: Vec<AvailableUser>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_available_user() -> AvailableUser {
        AvailableUser {
            uuid: "user-uuid-123".to_string(),
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
        }
    }

    #[test]
    fn test_available_user_creation() {
        let user = create_test_available_user();
        assert_eq!(user.username, "testuser");
    }

    #[test]
    fn test_group_add_member_template_renders() {
        use crate::templates::base::{UserContext, VaubanConfig};

        let template = GroupAddMemberTemplate {
            title: "Add Member".to_string(),
            user: Some(UserContext {
                uuid: "admin-uuid".to_string(),
                username: "admin".to_string(),
                display_name: "Admin User".to_string(),
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
            group: GroupInfo {
                uuid: "group-uuid".to_string(),
                name: "Test Group".to_string(),
            },
            available_users: vec![create_test_available_user()],
        };

        let result = template.render();
        assert!(result.is_ok(), "GroupAddMemberTemplate should render");
    }

    #[test]
    fn test_group_add_member_template_empty_users() {
        use crate::templates::base::{UserContext, VaubanConfig};

        let template = GroupAddMemberTemplate {
            title: "Add Member".to_string(),
            user: Some(UserContext {
                uuid: "admin-uuid".to_string(),
                username: "admin".to_string(),
                display_name: "Admin User".to_string(),
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
            group: GroupInfo {
                uuid: "group-uuid".to_string(),
                name: "Test Group".to_string(),
            },
            available_users: vec![],
        };

        let result = template.render();
        assert!(result.is_ok(), "Template should render with empty user list");
    }
}
