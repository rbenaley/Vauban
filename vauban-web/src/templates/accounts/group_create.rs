/// VAUBAN Web - Group create template.
use askama::Template;

use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};

#[derive(Template)]
#[template(path = "accounts/group_create.html")]
pub struct GroupCreateTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub csrf_token: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_group_create_template_renders() {
        use crate::templates::base::{UserContext, VaubanConfig};

        let template = GroupCreateTemplate {
            title: "Create Group".to_string(),
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
            csrf_token: "test-csrf-token".to_string(),
        };

        let result = template.render();
        assert!(result.is_ok(), "GroupCreateTemplate should render");
    }
}
