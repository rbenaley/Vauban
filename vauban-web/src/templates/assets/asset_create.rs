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
    pub port: i32,
    pub asset_type: String,
    pub status: String,
    pub description: Option<String>,
    pub csrf_token: String,
    // SSH credentials
    pub ssh_username: Option<String>,
    pub ssh_auth_type: Option<String>,
    pub ssh_password: Option<String>,
    pub ssh_private_key: Option<String>,
    pub ssh_passphrase: Option<String>,
    /// SSH key source: `generated` | `existing` (defaults to
    /// `generated` in the form when absent).
    pub ssh_key_source: Option<String>,
    /// Optional Windows AD domain shown only for RDP assets.
    pub rdp_domain: Option<String>,
    /// RDP NLA auth mode (`ntlm` | `kerberos_restricted_admin`), shown only
    /// for RDP assets.
    pub rdp_auth_mode: Option<String>,
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
            ..Default::default()
        }
    }

    fn create_test_form() -> AssetCreateForm {
        AssetCreateForm {
            name: "".to_string(),
            hostname: "".to_string(),
            port: 22,
            asset_type: "ssh".to_string(),
            status: "online".to_string(),
            description: None,
            csrf_token: "test_token".to_string(),
            ssh_username: None,
            ssh_auth_type: None,
            ssh_password: None,
            ssh_private_key: None,
            ssh_passphrase: None,
            ssh_key_source: None,
            rdp_domain: None,
            rdp_auth_mode: None,
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
        assert!(
            result.is_ok(),
            "AssetCreateTemplate should render successfully"
        );
    }

    #[test]
    fn test_asset_create_template_uses_alpine_for_port_defaults() {
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

        let html = template.render().expect("render should succeed");
        assert!(
            html.contains("x-data") && html.contains("ssh: 22") && html.contains("rdp: 3389"),
            "Port defaults must be handled via Alpine.js x-data"
        );
        assert!(
            html.contains("x-model"),
            "Port input must use Alpine.js x-model binding"
        );
        assert!(
            html.contains("x-on:change"),
            "Asset type select must use Alpine.js x-on:change"
        );
    }

    #[test]
    fn test_asset_create_template_has_no_vnc_option() {
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
            ],
        };

        let html = template.render().expect("render should succeed");
        assert!(
            !html.contains("VNC") && !html.contains("vnc"),
            "Asset create page must not contain any VNC reference"
        );
    }

    #[test]
    fn test_asset_create_default_port_is_ssh() {
        let form = create_test_form();
        assert_eq!(form.port, 22, "Default port should be 22 (SSH)");
        assert_eq!(form.asset_type, "ssh", "Default asset type should be SSH");
    }
}
