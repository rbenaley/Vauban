use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};
/// VAUBAN Web - Asset group add asset template.
use askama::Template;

/// Available asset for selection.
#[derive(Debug, Clone)]
pub struct AvailableAsset {
    pub uuid: String,
    pub name: String,
    pub hostname: String,
    pub asset_type: String,
    pub status: String,
    /// True if the asset is already linked to the target group (cannot add twice).
    pub in_target_group: bool,
    /// Group names for memberships other than the target group (for labels / multi-dot).
    pub other_group_names: Vec<String>,
    pub allow_multiple_groups_per_asset: bool,
}

impl AvailableAsset {
    /// Selectable when not already in the target group, and when single-group mode allows it.
    pub fn is_available(&self) -> bool {
        if self.in_target_group {
            return false;
        }
        if !self.allow_multiple_groups_per_asset {
            return self.other_group_names.is_empty();
        }
        true
    }

    /// Show amber indicator: asset already in another group while multi-membership is allowed.
    pub fn show_multi_membership_dot(&self) -> bool {
        self.allow_multiple_groups_per_asset && !self.other_group_names.is_empty()
    }

    /// Returns CSS classes for the asset status badge.
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
}

/// Group summary for display.
#[derive(Debug, Clone)]
pub struct GroupSummary {
    pub uuid: String,
    pub name: String,
}

#[derive(Template)]
#[template(path = "assets/group_add_asset.html")]
pub struct AssetGroupAddAssetTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub group: GroupSummary,
    pub available_assets: Vec<AvailableAsset>,
    /// Count of assets that are selectable on this form.
    pub available_count: usize,
    pub allow_multiple_groups_per_asset: bool,
    pub csrf_token: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_available_asset(status: &str) -> AvailableAsset {
        AvailableAsset {
            uuid: "asset-uuid".to_string(),
            name: "Test Asset".to_string(),
            hostname: "test.example.com".to_string(),
            asset_type: "ssh".to_string(),
            status: status.to_string(),
            in_target_group: false,
            other_group_names: Vec::new(),
            allow_multiple_groups_per_asset: false,
        }
    }

    fn create_test_assigned_asset() -> AvailableAsset {
        AvailableAsset {
            uuid: "assigned-asset-uuid".to_string(),
            name: "Assigned Asset".to_string(),
            hostname: "assigned.example.com".to_string(),
            asset_type: "rdp".to_string(),
            status: "online".to_string(),
            in_target_group: false,
            other_group_names: vec!["Production Servers".to_string()],
            allow_multiple_groups_per_asset: false,
        }
    }

    fn create_test_group_summary() -> GroupSummary {
        GroupSummary {
            uuid: "group-uuid".to_string(),
            name: "Production Servers".to_string(),
        }
    }

    // Tests for AvailableAsset status_class()
    #[test]
    fn test_available_asset_status_class_online() {
        let item = create_test_available_asset("online");
        assert!(item.status_class().contains("green"));
    }

    #[test]
    fn test_available_asset_status_class_offline() {
        let item = create_test_available_asset("offline");
        assert!(item.status_class().contains("red"));
    }

    #[test]
    fn test_available_asset_status_class_maintenance() {
        let item = create_test_available_asset("maintenance");
        assert!(item.status_class().contains("yellow"));
    }

    #[test]
    fn test_available_asset_status_class_unknown() {
        let item = create_test_available_asset("unknown");
        assert!(item.status_class().contains("gray"));
    }

    // Tests for AvailableAsset struct
    #[test]
    fn test_available_asset_creation() {
        let item = create_test_available_asset("online");
        assert_eq!(item.name, "Test Asset");
        assert_eq!(item.hostname, "test.example.com");
    }

    #[test]
    fn test_available_asset_clone() {
        let item = create_test_available_asset("online");
        let cloned = item.clone();
        assert_eq!(item.uuid, cloned.uuid);
    }

    // Tests for GroupSummary struct
    #[test]
    fn test_group_summary_creation() {
        let group = create_test_group_summary();
        assert_eq!(group.name, "Production Servers");
    }

    #[test]
    fn test_group_summary_clone() {
        let group = create_test_group_summary();
        let cloned = group.clone();
        assert_eq!(group.uuid, cloned.uuid);
    }

    // Tests for template rendering
    #[test]
    fn test_asset_group_add_asset_template_renders_with_assets() {
        use crate::templates::base::{UserContext, VaubanConfig};

        let assets = vec![create_test_available_asset("online")];
        let available_count = assets.iter().filter(|a| a.is_available()).count();

        let template = AssetGroupAddAssetTemplate {
            title: "Add Asset".to_string(),
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
            group: create_test_group_summary(),
            available_assets: assets,
            available_count,
            allow_multiple_groups_per_asset: false,
            csrf_token: "test_csrf".to_string(),
        };

        let result = template.render();
        assert!(
            result.is_ok(),
            "AssetGroupAddAssetTemplate should render with assets"
        );
    }

    #[test]
    fn test_asset_group_add_asset_template_renders_empty() {
        use crate::templates::base::{UserContext, VaubanConfig};

        let template = AssetGroupAddAssetTemplate {
            title: "Add Asset".to_string(),
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
            group: create_test_group_summary(),
            available_assets: Vec::new(),
            available_count: 0,
            allow_multiple_groups_per_asset: false,
            csrf_token: "test_csrf".to_string(),
        };

        let result = template.render();
        assert!(
            result.is_ok(),
            "AssetGroupAddAssetTemplate should render empty"
        );
    }

    #[test]
    fn test_asset_group_add_asset_template_renders_with_mixed_assets() {
        use crate::templates::base::{UserContext, VaubanConfig};

        let assets = vec![
            create_test_available_asset("online"),
            create_test_assigned_asset(),
        ];
        let available_count = assets.iter().filter(|a| a.is_available()).count();
        assert_eq!(available_count, 1); // Only one is available

        let template = AssetGroupAddAssetTemplate {
            title: "Add Asset".to_string(),
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
            group: create_test_group_summary(),
            available_assets: assets,
            available_count,
            allow_multiple_groups_per_asset: false,
            csrf_token: "test_csrf".to_string(),
        };

        let result = template.render();
        assert!(
            result.is_ok(),
            "AssetGroupAddAssetTemplate should render with mixed assets"
        );

        let html = unwrap_ok!(result);
        // Check that both types of assets are rendered
        assert!(html.contains("available-asset")); // Available asset has this class
        assert!(html.contains("assigned-asset")); // Assigned asset has this class
        assert!(html.contains("Already in:")); // Assigned asset shows this message
    }

    #[test]
    fn test_available_asset_different_types() {
        let ssh = AvailableAsset {
            uuid: "1".to_string(),
            name: "SSH Server".to_string(),
            hostname: "ssh.example.com".to_string(),
            asset_type: "ssh".to_string(),
            status: "online".to_string(),
            in_target_group: false,
            other_group_names: Vec::new(),
            allow_multiple_groups_per_asset: false,
        };
        let rdp = AvailableAsset {
            uuid: "2".to_string(),
            name: "RDP Server".to_string(),
            hostname: "rdp.example.com".to_string(),
            asset_type: "rdp".to_string(),
            status: "online".to_string(),
            in_target_group: false,
            other_group_names: Vec::new(),
            allow_multiple_groups_per_asset: false,
        };

        assert_eq!(ssh.asset_type, "ssh");
        assert_eq!(rdp.asset_type, "rdp");
    }

    // Tests for is_available()
    #[test]
    fn test_available_asset_is_available_true() {
        let asset = create_test_available_asset("online");
        assert!(asset.is_available());
        assert!(asset.other_group_names.is_empty());
    }

    #[test]
    fn test_available_asset_is_available_false_when_assigned() {
        let asset = create_test_assigned_asset();
        assert!(!asset.is_available());
        assert_eq!(asset.other_group_names.len(), 1);
        assert_eq!(
            unwrap_some!(asset.other_group_names.first()),
            "Production Servers"
        );
    }

    #[test]
    fn test_assigned_asset_creation() {
        let asset = create_test_assigned_asset();
        assert_eq!(asset.name, "Assigned Asset");
        assert_eq!(asset.hostname, "assigned.example.com");
        assert!(!asset.other_group_names.is_empty());
    }

    #[test]
    fn test_assigned_asset_status_class_still_works() {
        let asset = create_test_assigned_asset();
        // Even assigned assets should have correct status class
        assert!(asset.status_class().contains("green"));
    }

    #[test]
    fn test_show_multi_membership_dot_when_multi_and_other_groups() {
        let mut a = create_test_assigned_asset();
        a.allow_multiple_groups_per_asset = true;
        assert!(a.show_multi_membership_dot());
        assert!(a.is_available());
    }

    #[test]
    fn test_asset_group_add_asset_template_renders_multi_pastille() {
        use crate::templates::base::{UserContext, VaubanConfig};

        let mut multi = create_test_assigned_asset();
        multi.allow_multiple_groups_per_asset = true;

        let assets = vec![multi];
        let available_count = assets.iter().filter(|a| a.is_available()).count();
        assert_eq!(available_count, 1);

        let template = AssetGroupAddAssetTemplate {
            title: "Add Asset".to_string(),
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
            group: create_test_group_summary(),
            available_assets: assets,
            available_count,
            allow_multiple_groups_per_asset: true,
            csrf_token: "test_csrf".to_string(),
        };

        let html = unwrap_ok!(template.render());
        assert!(
            html.contains("bg-amber-500"),
            "Multi-group indicator should render amber pastille"
        );
        assert!(html.contains("Also belongs to another asset group"));
    }
}
