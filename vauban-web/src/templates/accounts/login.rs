/// VAUBAN Web - Login template.

use askama::Template;
use crate::templates::base::{UserContext, VaubanConfig, FlashMessage};


#[derive(Template)]
#[template(path = "accounts/login.html")]
pub struct LoginTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content: Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
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

    #[test]
    fn test_login_template_creation() {
        let template = LoginTemplate {
            title: "Login".to_string(),
            user: None,
            vauban: create_test_vauban_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
        };

        assert_eq!(template.title, "Login");
        assert!(template.user.is_none());
    }

    #[test]
    fn test_login_template_with_messages() {
        let template = LoginTemplate {
            title: "Login".to_string(),
            user: None,
            vauban: create_test_vauban_config(),
            messages: vec![
                FlashMessage { level: "error".to_string(), message: "Invalid credentials".to_string() },
            ],
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
        };

        assert_eq!(template.messages.len(), 1);
        assert_eq!(template.messages[0].level, "error");
    }

    #[test]
    fn test_login_template_renders() {
        let template = LoginTemplate {
            title: "Login".to_string(),
            user: None,
            vauban: create_test_vauban_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
        };

        let result = template.render();
        assert!(result.is_ok());
        let html = result.unwrap();
        assert!(html.contains("Login"));
    }
}

