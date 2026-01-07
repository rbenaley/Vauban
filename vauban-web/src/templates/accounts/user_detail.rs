use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};
/// VAUBAN Web - User detail template.
use askama::Template;

/// User detail information.
#[derive(Debug, Clone)]
pub struct UserDetail {
    pub uuid: String,
    pub username: String,
    pub email: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub phone: Option<String>,
    pub full_name: Option<String>,
    pub is_active: bool,
    pub is_staff: bool,
    pub is_superuser: bool,
    pub mfa_enabled: bool,
    pub auth_source: String,
    pub last_login: Option<String>,
    pub created_at: String,
}

#[derive(Template)]
#[template(path = "accounts/user_detail.html")]
pub struct UserDetailTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub user_detail: UserDetail,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_user_detail() -> UserDetail {
        UserDetail {
            uuid: "user-uuid-123".to_string(),
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            first_name: Some("Test".to_string()),
            last_name: Some("User".to_string()),
            phone: Some("+1234567890".to_string()),
            full_name: Some("Test User".to_string()),
            is_active: true,
            is_staff: false,
            is_superuser: false,
            mfa_enabled: true,
            auth_source: "local".to_string(),
            last_login: Some("2026-01-03 10:00:00".to_string()),
            created_at: "2026-01-01 00:00:00".to_string(),
        }
    }

    #[test]
    fn test_user_detail_creation() {
        let detail = create_test_user_detail();
        assert_eq!(detail.username, "testuser");
        assert!(detail.is_active);
        assert!(detail.mfa_enabled);
    }

    #[test]
    fn test_user_detail_without_optional_fields() {
        let mut detail = create_test_user_detail();
        detail.first_name = None;
        detail.last_name = None;
        detail.phone = None;
        detail.full_name = None;
        detail.last_login = None;

        assert!(detail.first_name.is_none());
        assert!(detail.last_login.is_none());
    }

    #[test]
    fn test_user_detail_superuser() {
        let mut detail = create_test_user_detail();
        detail.is_superuser = true;
        detail.is_staff = true;

        assert!(detail.is_superuser);
        assert!(detail.is_staff);
    }

    #[test]
    fn test_user_detail_clone() {
        let detail = create_test_user_detail();
        let cloned = detail.clone();
        assert_eq!(detail.uuid, cloned.uuid);
        assert_eq!(detail.email, cloned.email);
    }
}
