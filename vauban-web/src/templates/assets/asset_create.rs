/// VAUBAN Web - Asset create template.
use askama::Template;
use serde::Deserialize;
use validator::Validate;

use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};

/// Form data for asset creation.
#[derive(Debug, Default, Clone, Deserialize, Validate)]
pub struct AssetCreateForm {
    #[validate(length(min = 1, max = 100))]
    pub name: String,
    #[validate(length(min = 1, max = 255))]
    pub hostname: String,
    pub ip_address: Option<String>,
    pub port: i32,
    pub asset_type: String,
    pub status: String,
    pub description: Option<String>,
    pub require_mfa: bool,
    pub require_justification: bool,
    pub csrf_token: String,
}

#[derive(Template)]
#[template(path = "assets/asset_create.html")]
pub struct AssetCreateTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub form: AssetCreateForm,
    pub csrf_token: String,
    pub asset_types: Vec<(String, String)>,
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

    fn create_test_form() -> AssetCreateForm {
        AssetCreateForm {
            name: "".to_string(),
            hostname: "".to_string(),
            ip_address: None,
            port: 22,
            asset_type: "ssh".to_string(),
            status: "online".to_string(),
            description: None,
            require_mfa: false,
            require_justification: false,
            csrf_token: "test_token".to_string(),
        }
    }

    #[test]
    fn test_asset_create_form_default() {
        let form = AssetCreateForm::default();
        assert!(form.name.is_empty());
        assert!(form.hostname.is_empty());
    }

    #[test]
    fn test_asset_create_template_creation() {
        let template = AssetCreateTemplate {
            title: "New Asset".to_string(),
            user: None,
            vauban: create_test_vauban_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
            form: create_test_form(),
            csrf_token: "test".to_string(),
            asset_types: vec![
                ("ssh".to_string(), "SSH".to_string()),
                ("rdp".to_string(), "RDP".to_string()),
                ("vnc".to_string(), "VNC".to_string()),
            ],
        };
        assert_eq!(template.title, "New Asset");
    }

    #[test]
    fn test_asset_create_template_with_user() {
        let user = UserContext {
            uuid: "user-uuid".to_string(),
            username: "admin".to_string(),
            display_name: "Admin User".to_string(),
            is_superuser: true,
            is_staff: true,
        };

        let template = AssetCreateTemplate {
            title: "New Asset".to_string(),
            user: Some(user.clone()),
            vauban: create_test_vauban_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: Some(user),
            form: create_test_form(),
            csrf_token: "test".to_string(),
            asset_types: vec![],
        };

        assert!(template.user.is_some());
        assert_eq!(unwrap_some!(template.user.as_ref()).username, "admin");
    }

    #[test]
    fn test_asset_create_template_renders() {
        let template = AssetCreateTemplate {
            title: "New Asset".to_string(),
            user: Some(UserContext {
                uuid: "test".to_string(),
                username: "testuser".to_string(),
                display_name: "Test User".to_string(),
                is_superuser: true,
                is_staff: true,
            }),
            vauban: create_test_vauban_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
            form: create_test_form(),
            csrf_token: "test".to_string(),
            asset_types: vec![
                ("ssh".to_string(), "SSH".to_string()),
                ("rdp".to_string(), "RDP".to_string()),
            ],
        };

        let result = template.render();
        assert!(result.is_ok(), "AssetCreateTemplate should render successfully");
    }
}
