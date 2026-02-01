/// VAUBAN Web - User edit template.
use askama::Template;

use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};

/// User data for edit form.
#[derive(Debug, Clone)]
pub struct UserEditData {
    pub uuid: String,
    pub username: String,
    pub email: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub is_active: bool,
    pub is_staff: bool,
    pub is_superuser: bool,
}

#[derive(Template)]
#[template(path = "accounts/user_edit.html")]
pub struct UserEditTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    /// User data to edit
    pub user_data: UserEditData,
    /// Minimum password length from configuration
    pub password_min_length: usize,
    /// Whether the current user can manage superusers (is_superuser)
    pub can_manage_superusers: bool,
    /// Whether the current user can delete this user
    pub can_delete: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_user_data() -> UserEditData {
        UserEditData {
            uuid: "user-uuid-123".to_string(),
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            first_name: Some("Test".to_string()),
            last_name: Some("User".to_string()),
            is_active: true,
            is_staff: false,
            is_superuser: false,
        }
    }

    #[test]
    fn test_user_edit_data_creation() {
        let data = create_test_user_data();
        assert_eq!(data.username, "testuser");
        assert!(data.is_active);
        assert!(!data.is_superuser);
    }

    #[test]
    fn test_user_edit_template_renders() {
        use crate::templates::base::{UserContext, VaubanConfig};

        let template = UserEditTemplate {
            title: "Edit User".to_string(),
            user: Some(UserContext {
                uuid: "admin-uuid".to_string(),
                username: "admin".to_string(),
                display_name: "Admin User".to_string(),
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
            user_data: create_test_user_data(),
            password_min_length: 12,
            can_manage_superusers: true,
            can_delete: true,
        };

        let result = template.render();
        assert!(result.is_ok(), "UserEditTemplate should render");
    }

    #[test]
    fn test_user_edit_template_staff_cannot_edit_superuser() {
        use crate::templates::base::{UserContext, VaubanConfig};

        let mut user_data = create_test_user_data();
        user_data.is_superuser = true;

        let template = UserEditTemplate {
            title: "Edit User".to_string(),
            user: Some(UserContext {
                uuid: "staff-uuid".to_string(),
                username: "staff".to_string(),
                display_name: "Staff User".to_string(),
                is_superuser: false,
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
            user_data,
            password_min_length: 12,
            can_manage_superusers: false,
            can_delete: false,
        };

        let result = template.render();
        assert!(
            result.is_ok(),
            "UserEditTemplate should render for staff viewing superuser"
        );
    }
}
