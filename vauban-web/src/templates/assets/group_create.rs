/// VAUBAN Web - Asset group create template.
use askama::Template;

use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};

/// Form data for asset group creation.
#[derive(Debug, Default, Clone)]
pub struct AssetGroupCreateForm {
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub color: String,
    pub icon: String,
}

#[derive(Template)]
#[template(path = "assets/group_create.html")]
pub struct AssetGroupCreateTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub form: AssetGroupCreateForm,
    pub csrf_token: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_vauban_config() -> VaubanConfig {
        VaubanConfig {
            brand_name: "VAUBAN".to_string(),
            brand_logo: None,
            theme: "dark".to_string(),
        }
    }

    fn create_test_form() -> AssetGroupCreateForm {
        AssetGroupCreateForm {
            name: "".to_string(),
            slug: "".to_string(),
            description: None,
            color: "#6366f1".to_string(),
            icon: "server".to_string(),
        }
    }

    #[test]
    fn test_asset_group_create_form_default() {
        let form = AssetGroupCreateForm::default();
        assert!(form.name.is_empty());
        assert!(form.slug.is_empty());
    }

    #[test]
    fn test_asset_group_create_template_creation() {
        let template = AssetGroupCreateTemplate {
            title: "New Asset Group".to_string(),
            user: None,
            vauban: create_test_vauban_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
            form: create_test_form(),
            csrf_token: "test".to_string(),
        };
        assert_eq!(template.title, "New Asset Group");
    }

    #[test]
    fn test_asset_group_create_template_with_user() {
        let user = UserContext {
            uuid: "user-uuid".to_string(),
            username: "admin".to_string(),
            display_name: "Admin User".to_string(),
            is_superuser: true,
            is_staff: true,
        };

        let template = AssetGroupCreateTemplate {
            title: "New Asset Group".to_string(),
            user: Some(user.clone()),
            vauban: create_test_vauban_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: Some(user),
            form: create_test_form(),
            csrf_token: "test".to_string(),
        };

        assert!(template.user.is_some());
        assert_eq!(unwrap_some!(template.user.as_ref()).username, "admin");
    }

    #[test]
    fn test_asset_group_create_template_renders() {
        let template = AssetGroupCreateTemplate {
            title: "New Asset Group".to_string(),
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
            form: create_test_form(),
            csrf_token: "test".to_string(),
        };

        let result = template.render();
        assert!(
            result.is_ok(),
            "AssetGroupCreateTemplate should render successfully"
        );
    }
}
