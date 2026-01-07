use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};
/// VAUBAN Web - API key list template.
use askama::Template;

#[derive(Template)]
#[template(path = "accounts/apikey_list.html")]
pub struct ApikeyListTemplate {
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

    #[test]
    fn test_apikey_list_template_creation() {
        let template = ApikeyListTemplate {
            title: "API Keys".to_string(),
            user: None,
            vauban: create_test_vauban_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
        };
        assert_eq!(template.title, "API Keys");
        assert!(template.user.is_none());
    }

    #[test]
    fn test_apikey_list_template_with_messages() {
        let template = ApikeyListTemplate {
            title: "API Keys".to_string(),
            user: None,
            vauban: create_test_vauban_config(),
            messages: vec![FlashMessage {
                level: "success".to_string(),
                message: "Key created".to_string(),
            }],
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
        };
        assert_eq!(template.messages.len(), 1);
    }

    #[test]
    fn test_apikey_list_template_renders() {
        let template = ApikeyListTemplate {
            title: "API Keys".to_string(),
            user: None,
            vauban: create_test_vauban_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
        };
        let result = template.render();
        assert!(result.is_ok());
    }
}
