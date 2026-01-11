use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};
/// VAUBAN Web - Asset detail template.
use askama::Template;

/// Asset detail data.
#[derive(Debug, Clone)]
pub struct AssetDetail {
    pub uuid: String,
    pub name: String,
    pub hostname: String,
    pub ip_address: Option<String>,
    pub port: i32,
    pub asset_type: String,
    pub status: String,
    pub group_name: Option<String>,
    pub group_uuid: Option<String>,
    pub description: Option<String>,
    pub os_type: Option<String>,
    pub os_version: Option<String>,
    pub require_mfa: bool,
    pub require_justification: bool,
    pub max_session_duration: i32,
    pub last_seen: Option<String>,
    pub created_at: String,
    pub updated_at: String,
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
            "vnc" => "bg-purple-100 text-purple-800 dark:bg-purple-900/50 dark:text-purple-300",
            _ => "bg-gray-100 text-gray-800 dark:bg-gray-900/50 dark:text-gray-300",
        }
    }

    /// Format max session duration.
    pub fn max_session_display(&self) -> String {
        let hours = self.max_session_duration / 3600;
        let minutes = (self.max_session_duration % 3600) / 60;
        if hours > 0 {
            format!("{}h {}m", hours, minutes)
        } else {
            format!("{}m", minutes)
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
            ip_address: Some("192.168.1.100".to_string()),
            port: 22,
            asset_type: asset_type.to_string(),
            status: status.to_string(),
            group_name: Some("Production".to_string()),
            group_uuid: Some("group-uuid".to_string()),
            description: Some("Test server description".to_string()),
            os_type: Some("Linux".to_string()),
            os_version: Some("Ubuntu 22.04".to_string()),
            require_mfa: true,
            require_justification: false,
            max_session_duration: 7200,
            last_seen: Some("2026-01-03 10:00:00".to_string()),
            created_at: "2026-01-01 00:00:00".to_string(),
            updated_at: "2026-01-02 00:00:00".to_string(),
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
    fn test_type_class_vnc() {
        let asset = create_test_asset_detail("online", "vnc");
        assert!(asset.type_class().contains("purple"));
    }

    #[test]
    fn test_type_class_unknown() {
        let asset = create_test_asset_detail("online", "telnet");
        assert!(asset.type_class().contains("gray"));
    }

    // Tests for max_session_display()
    #[test]
    fn test_max_session_display_hours() {
        let asset = create_test_asset_detail("online", "ssh");
        assert_eq!(asset.max_session_display(), "2h 0m");
    }

    #[test]
    fn test_max_session_display_minutes_only() {
        let mut asset = create_test_asset_detail("online", "ssh");
        asset.max_session_duration = 1800; // 30 minutes
        assert_eq!(asset.max_session_display(), "30m");
    }

    #[test]
    fn test_max_session_display_hours_and_minutes() {
        let mut asset = create_test_asset_detail("online", "ssh");
        asset.max_session_duration = 5400; // 1h 30m
        assert_eq!(asset.max_session_display(), "1h 30m");
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
        use crate::templates::base::{VaubanConfig, UserContext};

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
}
