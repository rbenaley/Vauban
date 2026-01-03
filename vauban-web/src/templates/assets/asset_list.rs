/// VAUBAN Web - Asset list template.

use askama::Template;
use crate::templates::base::{UserContext, VaubanConfig, FlashMessage};

use crate::templates::accounts::user_list::Pagination;

/// Asset item for list display.
#[derive(Debug, Clone)]
pub struct AssetListItem {
    pub id: i32,
    pub name: String,
    pub hostname: String,
    pub port: i32,
    pub asset_type: String, // "ssh", "rdp", "vnc"
    pub status: String, // "online", "offline", "maintenance"
    pub group_name: Option<String>,
}

#[derive(Template)]
#[template(path = "assets/asset_list.html")]
pub struct AssetListTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content: Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub assets: Vec<AssetListItem>,
    pub pagination: Option<Pagination>,
    pub search: Option<String>,
    pub type_filter: Option<String>,
    pub status_filter: Option<String>,
    pub asset_types: Vec<(String, String)>,
    pub statuses: Vec<(String, String)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_asset_item() -> AssetListItem {
        AssetListItem {
            id: 1,
            name: "Test Server".to_string(),
            hostname: "test.example.com".to_string(),
            port: 22,
            asset_type: "ssh".to_string(),
            status: "online".to_string(),
            group_name: Some("Production".to_string()),
        }
    }

    #[test]
    fn test_asset_list_item_creation() {
        let item = create_test_asset_item();
        assert_eq!(item.name, "Test Server");
        assert_eq!(item.port, 22);
    }

    #[test]
    fn test_asset_list_item_without_group() {
        let mut item = create_test_asset_item();
        item.group_name = None;
        assert!(item.group_name.is_none());
    }

    #[test]
    fn test_asset_list_item_clone() {
        let item = create_test_asset_item();
        let cloned = item.clone();
        assert_eq!(item.id, cloned.id);
        assert_eq!(item.hostname, cloned.hostname);
    }

    #[test]
    fn test_asset_list_item_types() {
        let ssh = AssetListItem { asset_type: "ssh".to_string(), ..create_test_asset_item() };
        let rdp = AssetListItem { asset_type: "rdp".to_string(), ..create_test_asset_item() };
        let vnc = AssetListItem { asset_type: "vnc".to_string(), ..create_test_asset_item() };
        
        assert_eq!(ssh.asset_type, "ssh");
        assert_eq!(rdp.asset_type, "rdp");
        assert_eq!(vnc.asset_type, "vnc");
    }

    #[test]
    fn test_asset_list_item_statuses() {
        let online = AssetListItem { status: "online".to_string(), ..create_test_asset_item() };
        let offline = AssetListItem { status: "offline".to_string(), ..create_test_asset_item() };
        let maint = AssetListItem { status: "maintenance".to_string(), ..create_test_asset_item() };
        
        assert_eq!(online.status, "online");
        assert_eq!(offline.status, "offline");
        assert_eq!(maint.status, "maintenance");
    }
}
