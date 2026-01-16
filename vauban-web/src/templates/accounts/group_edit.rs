/// VAUBAN Web - Group edit template.
use askama::Template;

use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};

/// Group data for edit form.
#[derive(Debug, Clone)]
pub struct GroupEditData {
    pub uuid: String,
    pub name: String,
    pub description: Option<String>,
    pub source: String,
}

#[derive(Template)]
#[template(path = "accounts/group_edit.html")]
pub struct GroupEditTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub group: GroupEditData,
    pub csrf_token: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_group_data() -> GroupEditData {
        GroupEditData {
            uuid: "group-uuid-123".to_string(),
            name: "Test Group".to_string(),
            description: Some("A test group".to_string()),
            source: "local".to_string(),
        }
    }

    #[test]
    fn test_group_edit_data_creation() {
        let data = create_test_group_data();
        assert_eq!(data.name, "Test Group");
        assert_eq!(data.source, "local");
    }

    #[test]
    fn test_group_edit_template_renders() {
        use crate::templates::base::{UserContext, VaubanConfig};

        let template = GroupEditTemplate {
            title: "Edit Group".to_string(),
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
            group: create_test_group_data(),
            csrf_token: "test-csrf-token".to_string(),
        };

        let result = template.render();
        assert!(result.is_ok(), "GroupEditTemplate should render");
    }
}
