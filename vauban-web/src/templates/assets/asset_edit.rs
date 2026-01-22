/// VAUBAN Web - Asset edit template.
use askama::Template;

use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};

/// Asset data for editing.
#[derive(Debug, Clone)]
pub struct AssetEdit {
    pub uuid: String,
    pub name: String,
    pub hostname: String,
    pub ip_address: Option<String>,
    pub port: i32,
    pub asset_type: String,
    pub status: String,
    pub description: Option<String>,
    pub require_mfa: bool,
    pub require_justification: bool,
}

#[derive(Template)]
#[template(path = "assets/asset_edit.html")]
pub struct AssetEditTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub asset: AssetEdit,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{unwrap_ok, unwrap_some};

    fn create_test_asset_edit() -> AssetEdit {
        AssetEdit {
            uuid: "asset-uuid-123".to_string(),
            name: "Production Server".to_string(),
            hostname: "prod-01.example.com".to_string(),
            ip_address: Some("192.168.1.100".to_string()),
            port: 22,
            asset_type: "ssh".to_string(),
            status: "online".to_string(),
            description: Some("Main production server".to_string()),
            require_mfa: true,
            require_justification: false,
        }
    }

    fn create_test_vauban_config() -> VaubanConfig {
        VaubanConfig {
            brand_name: "VAUBAN".to_string(),
            brand_logo: None,
            theme: "dark".to_string(),
        }
    }

    #[test]
    fn test_asset_edit_creation() {
        let asset = create_test_asset_edit();
        assert_eq!(asset.name, "Production Server");
        assert_eq!(asset.hostname, "prod-01.example.com");
        assert_eq!(asset.port, 22);
        assert!(asset.require_mfa);
    }

    #[test]
    fn test_asset_edit_without_ip_address() {
        let mut asset = create_test_asset_edit();
        asset.ip_address = None;
        assert!(asset.ip_address.is_none());
    }

    #[test]
    fn test_asset_edit_without_description() {
        let mut asset = create_test_asset_edit();
        asset.description = None;
        assert!(asset.description.is_none());
    }

    #[test]
    fn test_asset_edit_clone() {
        let asset = create_test_asset_edit();
        let cloned = asset.clone();
        assert_eq!(asset.uuid, cloned.uuid);
        assert_eq!(asset.name, cloned.name);
        assert_eq!(asset.hostname, cloned.hostname);
    }

    #[test]
    fn test_asset_edit_debug() {
        let asset = create_test_asset_edit();
        let debug_str = format!("{:?}", asset);
        assert!(debug_str.contains("Production Server"));
        assert!(debug_str.contains("ssh"));
    }

    #[test]
    fn test_asset_edit_template_creation() {
        let template = AssetEditTemplate {
            title: "Edit Asset".to_string(),
            user: None,
            vauban: create_test_vauban_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
            asset: create_test_asset_edit(),
        };
        assert_eq!(template.title, "Edit Asset");
        assert_eq!(template.asset.name, "Production Server");
    }

    #[test]
    fn test_asset_edit_template_with_user() {
        let user = UserContext {
            uuid: "user-uuid".to_string(),
            username: "admin".to_string(),
            display_name: "Admin User".to_string(),
            is_superuser: true,
            is_staff: true,
        };

        let template = AssetEditTemplate {
            title: "Edit Asset".to_string(),
            user: Some(user.clone()),
            vauban: create_test_vauban_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: Some(user),
            asset: create_test_asset_edit(),
        };

        assert!(template.user.is_some());
        assert_eq!(unwrap_some!(template.user.as_ref()).username, "admin");
    }

    #[test]
    fn test_asset_edit_template_renders() {
        let template = AssetEditTemplate {
            title: "Edit Asset".to_string(),
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
            asset: create_test_asset_edit(),
        };

        let result = template.render();
        assert!(result.is_ok(), "AssetEditTemplate should render successfully");
    }

    #[test]
    fn test_asset_edit_rdp_type() {
        let mut asset = create_test_asset_edit();
        asset.asset_type = "rdp".to_string();
        asset.port = 3389;
        assert_eq!(asset.asset_type, "rdp");
        assert_eq!(asset.port, 3389);
    }

    #[test]
    fn test_asset_edit_vnc_type() {
        let mut asset = create_test_asset_edit();
        asset.asset_type = "vnc".to_string();
        asset.port = 5900;
        assert_eq!(asset.asset_type, "vnc");
        assert_eq!(asset.port, 5900);
    }

    #[test]
    fn test_asset_edit_all_statuses() {
        let mut asset = create_test_asset_edit();
        
        for status in ["online", "offline", "maintenance", "unknown"] {
            asset.status = status.to_string();
            assert_eq!(asset.status, status);
        }
    }
}
