use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};
/// VAUBAN Web - Asset group list template.
use askama::Template;

/// Asset group item for list display.
#[derive(Debug, Clone)]
pub struct AssetGroupItem {
    pub uuid: String,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub color: String,
    pub icon: String,
    pub asset_count: i64,
    pub created_at: String,
}

#[derive(Template)]
#[template(path = "assets/group_list.html")]
pub struct AssetGroupListTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub groups: Vec<AssetGroupItem>,
    pub search: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_asset_group_item() -> AssetGroupItem {
        AssetGroupItem {
            uuid: "group-uuid".to_string(),
            name: "Production Servers".to_string(),
            slug: "production".to_string(),
            description: Some("Production environment".to_string()),
            color: "#10b981".to_string(),
            icon: "server".to_string(),
            asset_count: 10,
            created_at: "2026-01-01 00:00:00".to_string(),
        }
    }

    #[test]
    fn test_asset_group_item_creation() {
        let item = create_test_asset_group_item();
        assert_eq!(item.name, "Production Servers");
        assert_eq!(item.asset_count, 10);
    }

    #[test]
    fn test_asset_group_item_without_description() {
        let mut item = create_test_asset_group_item();
        item.description = None;
        assert!(item.description.is_none());
    }

    #[test]
    fn test_asset_group_item_clone() {
        let item = create_test_asset_group_item();
        let cloned = item.clone();
        assert_eq!(item.uuid, cloned.uuid);
        assert_eq!(item.asset_count, cloned.asset_count);
    }

    #[test]
    fn test_asset_group_item_zero_assets() {
        let mut item = create_test_asset_group_item();
        item.asset_count = 0;
        assert_eq!(item.asset_count, 0);
    }

    #[test]
    fn test_asset_group_list_template_renders() {
        use crate::templates::base::{UserContext, VaubanConfig};

        let template = AssetGroupListTemplate {
            title: "Asset Groups".to_string(),
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
            },
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
            groups: vec![create_test_asset_group_item()],
            search: None,
        };

        let result = template.render();
        assert!(result.is_ok(), "AssetGroupListTemplate should render");
    }
}
