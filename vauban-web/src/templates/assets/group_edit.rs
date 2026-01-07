use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};
/// VAUBAN Web - Asset group edit template.
use askama::Template;

/// Asset group data for editing.
#[derive(Debug, Clone)]
pub struct AssetGroupEdit {
    pub uuid: String,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub color: String,
    pub icon: String,
}

#[derive(Template)]
#[template(path = "assets/group_edit.html")]
pub struct AssetGroupEditTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub group: AssetGroupEdit,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_asset_group_edit() -> AssetGroupEdit {
        AssetGroupEdit {
            uuid: "group-uuid".to_string(),
            name: "Production Servers".to_string(),
            slug: "production".to_string(),
            description: Some("Production environment".to_string()),
            color: "#10b981".to_string(),
            icon: "server".to_string(),
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
    fn test_asset_group_edit_creation() {
        let group = create_test_asset_group_edit();
        assert_eq!(group.name, "Production Servers");
        assert_eq!(group.slug, "production");
    }

    #[test]
    fn test_asset_group_edit_without_description() {
        let mut group = create_test_asset_group_edit();
        group.description = None;
        assert!(group.description.is_none());
    }

    #[test]
    fn test_asset_group_edit_clone() {
        let group = create_test_asset_group_edit();
        let cloned = group.clone();
        assert_eq!(group.uuid, cloned.uuid);
        assert_eq!(group.color, cloned.color);
    }

    #[test]
    fn test_asset_group_edit_template_creation() {
        let template = AssetGroupEditTemplate {
            title: "Edit Group".to_string(),
            user: None,
            vauban: create_test_vauban_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
            group: create_test_asset_group_edit(),
        };
        assert_eq!(template.title, "Edit Group");
    }

    #[test]
    fn test_asset_group_edit_template_renders() {
        let template = AssetGroupEditTemplate {
            title: "Edit Group".to_string(),
            user: None,
            vauban: create_test_vauban_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
            group: create_test_asset_group_edit(),
        };
        let result = template.render();
        assert!(result.is_ok());
    }
}
