/// VAUBAN Web - User create template.
use askama::Template;

use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};

#[derive(Template)]
#[template(path = "accounts/user_create.html")]
pub struct UserCreateTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    /// Minimum password length from configuration
    pub password_min_length: usize,
    /// Whether the current user can manage superusers (is_superuser)
    pub can_manage_superusers: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_create_template_renders() {
        use crate::templates::base::{UserContext, VaubanConfig};

        let template = UserCreateTemplate {
            title: "New User".to_string(),
            user: Some(UserContext {
                uuid: "test".to_string(),
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
            password_min_length: 12,
            can_manage_superusers: true,
        };

        let result = template.render();
        assert!(result.is_ok(), "UserCreateTemplate should render");
    }

    #[test]
    fn test_user_create_template_without_superuser_permission() {
        use crate::templates::base::{UserContext, VaubanConfig};

        let template = UserCreateTemplate {
            title: "New User".to_string(),
            user: Some(UserContext {
                uuid: "test".to_string(),
                username: "staff".to_string(),
                display_name: "Staff User".to_string(),
                is_superuser: false,
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
            password_min_length: 12,
            can_manage_superusers: false,
        };

        let result = template.render();
        assert!(result.is_ok(), "UserCreateTemplate should render for staff");
    }
}
