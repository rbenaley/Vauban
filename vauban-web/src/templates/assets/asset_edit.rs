/// VAUBAN Web - Asset edit template.
use askama::Template;

use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};

/// Asset data for editing.
#[derive(Debug, Clone)]
pub struct AssetEdit {
    pub uuid: String,
    pub name: String,
    pub hostname: String,
    pub port: i32,
    pub asset_type: String,
    /// True when the row is an IACS applicative variant.
    pub is_iacs: bool,
    /// Compact 3-char label used by the square header tile so the
    /// long IACS variants ("iacs_modbus", ...) do not overflow the
    /// `h-10 w-10` square (see `AssetType::badge_label`).
    pub badge_label: String,
    pub status: String,
    pub description: Option<String>,
    // SSH credentials extracted from connection_config.
    //
    // Note: secret values (password, private key, passphrase) are
    // intentionally NOT exposed to the template. Surfacing the stored
    // ciphertext into a `<input type="password">` would (a) leak it
    // into browser DOM/autofill/history and (b) confuse operators with
    // a 200+ dot field that has nothing to do with their original
    // password length. We only expose presence booleans so the form
    // can render "Leave blank to keep current ..." hints when an
    // existing secret is on file.
    pub ssh_username: String,
    pub ssh_auth_type: String,
    pub has_password: bool,
    pub has_private_key: bool,
    pub has_passphrase: bool,
    /// SSH host key fingerprint (read-only, from connection_config).
    pub ssh_host_key_fingerprint: Option<String>,
    /// VAU-001: pinned RDP server-certificate fingerprint (read-only, from
    /// connection_config). `None` when no certificate has been pinned yet.
    pub rdp_server_cert_fingerprint: Option<String>,
    /// Windows AD domain extracted from connection_config (RDP only).
    pub rdp_domain: String,
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
    /// Industrial protocol choices for IACS asset edit (five variants).
    pub iacs_asset_types: Vec<(String, String)>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::asset::AssetType;

    fn create_test_asset_edit() -> AssetEdit {
        AssetEdit {
            uuid: "asset-uuid-123".to_string(),
            name: "Production Server".to_string(),
            hostname: "prod-01.example.com".to_string(),
            port: 22,
            asset_type: "ssh".to_string(),
            is_iacs: false,
            badge_label: "SSH".to_string(),
            status: "online".to_string(),
            description: Some("Main production server".to_string()),
            ssh_username: "root".to_string(),
            ssh_auth_type: "password".to_string(),
            has_password: false,
            has_private_key: false,
            has_passphrase: false,
            ssh_host_key_fingerprint: None,
            rdp_server_cert_fingerprint: None,
            rdp_domain: String::new(),
        }
    }

    fn create_test_vauban_config() -> VaubanConfig {
        VaubanConfig {
            brand_name: "VAUBAN".to_string(),
            brand_logo: None,
            theme: "dark".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn test_asset_edit_creation() {
        let asset = create_test_asset_edit();
        assert_eq!(asset.name, "Production Server");
        assert_eq!(asset.hostname, "prod-01.example.com");
        assert_eq!(asset.port, 22);
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
            iacs_asset_types: AssetType::iacs_select_options(),
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
            iacs_asset_types: AssetType::iacs_select_options(),
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
            iacs_asset_types: AssetType::iacs_select_options(),
        };

        let result = template.render();
        assert!(
            result.is_ok(),
            "AssetEditTemplate should render successfully"
        );
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
    fn test_asset_edit_all_statuses() {
        let mut asset = create_test_asset_edit();

        for status in ["online", "offline", "maintenance", "unknown"] {
            asset.status = status.to_string();
            assert_eq!(asset.status, status);
        }
    }
}
