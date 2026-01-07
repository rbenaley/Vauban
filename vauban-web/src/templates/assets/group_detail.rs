use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};
/// VAUBAN Web - Asset group detail template.
use askama::Template;

/// Asset in group for display.
#[derive(Debug, Clone)]
pub struct GroupAssetItem {
    pub uuid: String,
    pub name: String,
    pub hostname: String,
    pub asset_type: String,
    pub status: String,
}

impl GroupAssetItem {
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

/// Asset group detail data.
#[derive(Debug, Clone)]
pub struct AssetGroupDetail {
    pub uuid: String,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub color: String,
    pub icon: String,
    pub created_at: String,
    pub updated_at: String,
    pub assets: Vec<GroupAssetItem>,
}

#[derive(Template)]
#[template(path = "assets/group_detail.html")]
pub struct AssetGroupDetailTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub group: AssetGroupDetail,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_group_asset_item(status: &str) -> GroupAssetItem {
        GroupAssetItem {
            uuid: "asset-uuid".to_string(),
            name: "Test Asset".to_string(),
            hostname: "test.example.com".to_string(),
            asset_type: "ssh".to_string(),
            status: status.to_string(),
        }
    }

    fn create_test_asset_group_detail() -> AssetGroupDetail {
        AssetGroupDetail {
            uuid: "group-uuid".to_string(),
            name: "Production Servers".to_string(),
            slug: "production".to_string(),
            description: Some("Production environment".to_string()),
            color: "#10b981".to_string(),
            icon: "server".to_string(),
            created_at: "2026-01-01 00:00:00".to_string(),
            updated_at: "2026-01-02 00:00:00".to_string(),
            assets: vec![create_test_group_asset_item("online")],
        }
    }

    // Tests for GroupAssetItem status_class()
    #[test]
    fn test_group_asset_status_class_online() {
        let item = create_test_group_asset_item("online");
        assert!(item.status_class().contains("green"));
    }

    #[test]
    fn test_group_asset_status_class_offline() {
        let item = create_test_group_asset_item("offline");
        assert!(item.status_class().contains("red"));
    }

    #[test]
    fn test_group_asset_status_class_maintenance() {
        let item = create_test_group_asset_item("maintenance");
        assert!(item.status_class().contains("yellow"));
    }

    #[test]
    fn test_group_asset_status_class_unknown() {
        let item = create_test_group_asset_item("unknown");
        assert!(item.status_class().contains("gray"));
    }

    // Tests for GroupAssetItem struct
    #[test]
    fn test_group_asset_item_creation() {
        let item = create_test_group_asset_item("online");
        assert_eq!(item.name, "Test Asset");
    }

    #[test]
    fn test_group_asset_item_clone() {
        let item = create_test_group_asset_item("online");
        let cloned = item.clone();
        assert_eq!(item.uuid, cloned.uuid);
    }

    // Tests for AssetGroupDetail struct
    #[test]
    fn test_asset_group_detail_creation() {
        let group = create_test_asset_group_detail();
        assert_eq!(group.name, "Production Servers");
        assert_eq!(group.assets.len(), 1);
    }

    #[test]
    fn test_asset_group_detail_without_description() {
        let mut group = create_test_asset_group_detail();
        group.description = None;
        assert!(group.description.is_none());
    }

    #[test]
    fn test_asset_group_detail_clone() {
        let group = create_test_asset_group_detail();
        let cloned = group.clone();
        assert_eq!(group.uuid, cloned.uuid);
        assert_eq!(group.assets.len(), cloned.assets.len());
    }
}
