use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};
/// VAUBAN Web - Asset detail template.
use askama::Template;

/// Asset detail data.
#[derive(Debug, Clone)]
pub struct AssetDetail {
    pub uuid: String,
    pub name: String,
    pub hostname: String,
    pub port: i32,
    pub asset_type: String,
    pub status: String,
    pub group_name: Option<String>,
    pub group_uuid: Option<String>,
    pub description: Option<String>,
    pub require_approval: bool,
    pub require_mfa: bool,
    pub created_at: String,
    pub updated_at: String,
    /// SSH host key fingerprint (from connection_config JSONB).
    pub ssh_host_key_fingerprint: Option<String>,
    /// True when the stored host key is known to mismatch the server's current key.
    pub ssh_host_key_mismatch: bool,
    /// True when a valid (non-expired) approved JIT session exists for this user+asset.
    pub has_approved_session: bool,
    /// True when the platform requires a justification before connecting (SEC-03).
    pub require_justification: bool,
}

impl AssetDetail {
    /// Get status badge class.
    pub fn status_class(&self) -> &str {
        match self.status.as_str() {
            "online" => "bg-green-100 text-green-800 dark:bg-green-900/50 dark:text-green-300",
            "offline" => "bg-red-100 text-red-800 dark:bg-red-900/50 dark:text-red-300",
            "maintenance" => {
                "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/50 dark:text-yellow-300"
            }
            _ => "bg-gray-100 text-gray-800 dark:bg-gray-900/50 dark:text-gray-300",
        }
    }

    /// Get asset type badge class.
    pub fn type_class(&self) -> &str {
        match self.asset_type.as_str() {
            "ssh" => "bg-green-100 text-green-800 dark:bg-green-900/50 dark:text-green-300",
            "rdp" => "bg-blue-100 text-blue-800 dark:bg-blue-900/50 dark:text-blue-300",
            _ => "bg-gray-100 text-gray-800 dark:bg-gray-900/50 dark:text-gray-300",
        }
    }
}

#[derive(Template)]
#[template(path = "assets/asset_detail.html")]
pub struct AssetDetailTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub asset: AssetDetail,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_asset_detail(status: &str, asset_type: &str) -> AssetDetail {
        AssetDetail {
            uuid: "asset-uuid".to_string(),
            name: "Test Server".to_string(),
            hostname: "test.example.com".to_string(),
            port: 22,
            asset_type: asset_type.to_string(),
            status: status.to_string(),
            group_name: Some("Production".to_string()),
            group_uuid: Some("group-uuid".to_string()),
            description: Some("Test server description".to_string()),
            require_approval: false,
            require_mfa: true,
            created_at: "2026-01-01 00:00:00".to_string(),
            updated_at: "2026-01-02 00:00:00".to_string(),
            ssh_host_key_fingerprint: None,
            ssh_host_key_mismatch: false,
            has_approved_session: false,
            require_justification: true,
        }
    }

    // Tests for status_class()
    #[test]
    fn test_status_class_online() {
        let asset = create_test_asset_detail("online", "ssh");
        assert!(asset.status_class().contains("green"));
    }

    #[test]
    fn test_status_class_offline() {
        let asset = create_test_asset_detail("offline", "ssh");
        assert!(asset.status_class().contains("red"));
    }

    #[test]
    fn test_status_class_maintenance() {
        let asset = create_test_asset_detail("maintenance", "ssh");
        assert!(asset.status_class().contains("yellow"));
    }

    #[test]
    fn test_status_class_unknown() {
        let asset = create_test_asset_detail("unknown", "ssh");
        assert!(asset.status_class().contains("gray"));
    }

    // Tests for type_class()
    #[test]
    fn test_type_class_ssh() {
        let asset = create_test_asset_detail("online", "ssh");
        assert!(asset.type_class().contains("green"));
    }

    #[test]
    fn test_type_class_rdp() {
        let asset = create_test_asset_detail("online", "rdp");
        assert!(asset.type_class().contains("blue"));
    }

    #[test]
    fn test_type_class_unknown() {
        let asset = create_test_asset_detail("online", "telnet");
        assert!(asset.type_class().contains("gray"));
    }

    // Tests for AssetDetail struct
    #[test]
    fn test_asset_detail_creation() {
        let asset = create_test_asset_detail("online", "ssh");
        assert_eq!(asset.name, "Test Server");
        assert!(asset.require_mfa);
    }

    #[test]
    fn test_asset_detail_clone() {
        let asset = create_test_asset_detail("online", "rdp");
        let cloned = asset.clone();
        assert_eq!(asset.uuid, cloned.uuid);
    }

    #[test]
    fn test_asset_detail_template_renders() {
        use crate::templates::base::{UserContext, VaubanConfig};

        let template = AssetDetailTemplate {
            title: "Asset Detail".to_string(),
            user: Some(UserContext {
                uuid: "test".to_string(),
                username: "testuser".to_string(),
                display_name: "Test User".to_string(),
                is_superuser: true,
                is_staff: true,
            }),
            vauban: VaubanConfig {
                brand_name: "VAUBAN".to_string(),
                brand_logo: None,
                theme: "dark".to_string(),
                ..Default::default()
            },
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
            asset: create_test_asset_detail("online", "ssh"),
        };

        let result = template.render();
        assert!(result.is_ok(), "AssetDetailTemplate should render");
    }

    // ---- asset-policy-state div tests (JS hash-router defense-in-depth) ----

    fn asset_detail_template(require_approval: bool, has_approved: bool) -> AssetDetailTemplate {
        use crate::templates::base::{UserContext, VaubanConfig};
        let mut asset = create_test_asset_detail("online", "ssh");
        asset.require_approval = require_approval;
        asset.has_approved_session = has_approved;
        AssetDetailTemplate {
            title: "Asset".to_string(),
            user: Some(UserContext {
                uuid: "u".to_string(),
                username: "u".to_string(),
                display_name: "u".to_string(),
                is_superuser: false,
                is_staff: false,
            }),
            vauban: VaubanConfig::default(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
            asset,
        }
    }

    #[test]
    fn policy_state_div_present_with_approval_flag() {
        let html = asset_detail_template(true, false).render().expect("render");
        assert!(
            html.contains("id=\"asset-policy-state\""),
            "must contain policy-state div for JS hash-router"
        );
        assert!(
            html.contains("data-require-approval=\"true\""),
            "data-require-approval must reflect the policy"
        );
        assert!(
            html.contains("data-has-approved-session=\"false\""),
            "data-has-approved-session must reflect unapproved state"
        );
    }

    #[test]
    fn policy_state_div_reflects_approved_session() {
        let html = asset_detail_template(true, true).render().expect("render");
        assert!(
            html.contains("data-require-approval=\"true\""),
            "approval still required (rule exists)"
        );
        assert!(
            html.contains("data-has-approved-session=\"true\""),
            "approved session must be reflected"
        );
    }

    #[test]
    fn policy_state_no_approval_required() {
        let html = asset_detail_template(false, false).render().expect("render");
        assert!(
            html.contains("data-require-approval=\"false\""),
            "no approval required"
        );
    }
}
