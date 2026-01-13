use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};
/// VAUBAN Web - Dashboard home template.
use askama::Template;

/// Favorite asset for dashboard.
#[derive(Debug, Clone)]
pub struct FavoriteAsset {
    pub id: i32,
    pub uuid: ::uuid::Uuid,
    pub name: String,
    pub hostname: String,
    pub asset_type: String, // "ssh", "rdp", "vnc"
}

#[derive(Template)]
#[template(path = "dashboard/home.html")]
pub struct HomeTemplate {
    // Base template fields
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    // Page-specific fields
    pub favorite_assets: Vec<FavoriteAsset>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== FavoriteAsset Tests ====================

    #[test]
    fn test_favorite_asset_ssh() {
        let asset = FavoriteAsset {
            id: 1,
            uuid: ::uuid::Uuid::new_v4(),
            name: "Web Server".to_string(),
            hostname: "web.example.com".to_string(),
            asset_type: "ssh".to_string(),
        };

        assert_eq!(asset.id, 1);
        assert_eq!(asset.name, "Web Server");
        assert_eq!(asset.asset_type, "ssh");
    }

    #[test]
    fn test_favorite_asset_rdp() {
        let asset = FavoriteAsset {
            id: 2,
            uuid: ::uuid::Uuid::new_v4(),
            name: "Windows Server".to_string(),
            hostname: "win.example.com".to_string(),
            asset_type: "rdp".to_string(),
        };

        assert_eq!(asset.asset_type, "rdp");
    }

    #[test]
    fn test_favorite_asset_clone() {
        let asset = FavoriteAsset {
            id: 3,
            uuid: ::uuid::Uuid::new_v4(),
            name: "Database".to_string(),
            hostname: "db.example.com".to_string(),
            asset_type: "ssh".to_string(),
        };
        let cloned = asset.clone();

        assert_eq!(asset.id, cloned.id);
        assert_eq!(asset.name, cloned.name);
    }

    #[test]
    fn test_favorite_asset_debug() {
        let asset = FavoriteAsset {
            id: 4,
            uuid: ::uuid::Uuid::new_v4(),
            name: "Test".to_string(),
            hostname: "test.local".to_string(),
            asset_type: "vnc".to_string(),
        };
        let debug_str = format!("{:?}", asset);

        assert!(debug_str.contains("FavoriteAsset"));
        assert!(debug_str.contains("vnc"));
    }

    // ==================== HomeTemplate Tests ====================

    fn create_test_config() -> VaubanConfig {
        VaubanConfig {
            brand_name: "VAUBAN".to_string(),
            brand_logo: None,
            theme: "dark".to_string(),
        }
    }

    fn create_test_user() -> UserContext {
        UserContext {
            uuid: "user-123".to_string(),
            username: "testuser".to_string(),
            display_name: "Test User".to_string(),
            is_superuser: false,
            is_staff: false,
        }
    }

    #[test]
    fn test_home_template_creation() {
        let template = HomeTemplate {
            title: "Dashboard".to_string(),
            user: Some(create_test_user()),
            vauban: create_test_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: Some(create_test_user()),
            favorite_assets: Vec::new(),
        };

        assert_eq!(template.title, "Dashboard");
        assert!(template.user.is_some());
        assert!(template.favorite_assets.is_empty());
    }

    #[test]
    fn test_home_template_with_favorites() {
        let template = HomeTemplate {
            title: "Dashboard".to_string(),
            user: Some(create_test_user()),
            vauban: create_test_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: Some(create_test_user()),
            favorite_assets: vec![
                FavoriteAsset {
                    id: 1,
                    uuid: ::uuid::Uuid::new_v4(),
                    name: "Server 1".to_string(),
                    hostname: "s1.local".to_string(),
                    asset_type: "ssh".to_string(),
                },
                FavoriteAsset {
                    id: 2,
                    uuid: ::uuid::Uuid::new_v4(),
                    name: "Server 2".to_string(),
                    hostname: "s2.local".to_string(),
                    asset_type: "rdp".to_string(),
                },
            ],
        };

        assert_eq!(template.favorite_assets.len(), 2);
    }

    #[test]
    fn test_home_template_renders() {
        let template = HomeTemplate {
            title: "Dashboard".to_string(),
            user: Some(create_test_user()),
            vauban: create_test_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: Some(create_test_user()),
            favorite_assets: Vec::new(),
        };

        let result = template.render();
        assert!(result.is_ok());
    }
}
