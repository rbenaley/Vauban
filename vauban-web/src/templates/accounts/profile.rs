use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};
/// VAUBAN Web - User profile template.
use askama::Template;

#[derive(Template)]
#[template(path = "accounts/profile.html")]
pub struct ProfileTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_vauban_config() -> VaubanConfig {
        VaubanConfig {
            brand_name: "VAUBAN".to_string(),
            brand_logo: None,
            theme: "dark".to_string(),
        }
    }

    fn create_test_user_context() -> UserContext {
        UserContext {
            uuid: "user-uuid".to_string(),
            username: "testuser".to_string(),
            display_name: "Test User".to_string(),
            is_superuser: false,
            is_staff: false,
        }
    }

    #[test]
    fn test_profile_template_creation() {
        let template = ProfileTemplate {
            title: "Profile".to_string(),
            user: Some(create_test_user_context()),
            vauban: create_test_vauban_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: Some(create_test_user_context()),
        };
        assert_eq!(template.title, "Profile");
        assert!(template.user.is_some());
    }

    #[test]
    fn test_profile_template_renders() {
        let template = ProfileTemplate {
            title: "Profile".to_string(),
            user: Some(create_test_user_context()),
            vauban: create_test_vauban_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: Some(create_test_user_context()),
        };
        let result = template.render();
        assert!(result.is_ok());
    }
}
