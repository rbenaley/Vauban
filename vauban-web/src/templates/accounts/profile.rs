use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};
/// VAUBAN Web - User profile template.
use askama::Template;
use chrono::{DateTime, Utc};

/// Profile information for the current user.
#[derive(Debug, Clone)]
pub struct ProfileDetail {
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
    pub mfa_enforced: bool,
    pub auth_source: String,
    pub last_login: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Active session information for profile page.
#[derive(Debug, Clone)]
pub struct ProfileSession {
    pub uuid: String,
    pub ip_address: String,
    pub device_info: String,
    pub last_activity: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub is_current: bool,
}

impl ProfileSession {
    /// Get a human-readable description of the session age.
    pub fn age_display(&self) -> String {
        let duration = Utc::now().signed_duration_since(self.created_at);
        if duration.num_days() > 0 {
            format!("{} days ago", duration.num_days())
        } else if duration.num_hours() > 0 {
            format!("{} hours ago", duration.num_hours())
        } else if duration.num_minutes() > 0 {
            format!("{} minutes ago", duration.num_minutes())
        } else {
            "Just now".to_string()
        }
    }

    /// Get a human-readable description of last activity.
    pub fn last_activity_display(&self) -> String {
        let duration = Utc::now().signed_duration_since(self.last_activity);
        if duration.num_days() > 0 {
            format!("{} days ago", duration.num_days())
        } else if duration.num_hours() > 0 {
            format!("{} hours ago", duration.num_hours())
        } else if duration.num_minutes() > 0 {
            format!("{} minutes ago", duration.num_minutes())
        } else {
            "Just now".to_string()
        }
    }
}

#[derive(Template)]
#[template(path = "accounts/profile.html")]
pub struct ProfileTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub profile: ProfileDetail,
    pub sessions: Vec<ProfileSession>,
    pub current_session_token: Option<String>,
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

    fn create_test_user_context() -> UserContext {
        UserContext {
            uuid: "user-uuid".to_string(),
            username: "testuser".to_string(),
            display_name: "Test User".to_string(),
            is_superuser: false,
            is_staff: false,
        }
    }

    fn create_test_profile_detail() -> ProfileDetail {
        ProfileDetail {
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
            mfa_enabled: false,
            mfa_enforced: false,
            auth_source: "local".to_string(),
            last_login: Some("2026-01-10 10:00:00".to_string()),
            created_at: "2026-01-01 00:00:00".to_string(),
            updated_at: "2026-01-10 10:00:00".to_string(),
        }
    }

    fn create_test_session() -> ProfileSession {
        ProfileSession {
            uuid: "session-uuid-123".to_string(),
            ip_address: "192.168.1.1".to_string(),
            device_info: "Chrome on macOS".to_string(),
            last_activity: Utc::now(),
            created_at: Utc::now(),
            is_current: true,
        }
    }

    #[test]
    fn test_profile_detail_creation() {
        let profile = create_test_profile_detail();
        assert_eq!(profile.username, "testuser");
        assert!(profile.is_active);
        assert!(!profile.mfa_enabled);
    }

    #[test]
    fn test_profile_session_age_display() {
        let session = create_test_session();
        assert_eq!(session.age_display(), "Just now");
    }

    #[test]
    fn test_profile_session_last_activity_display() {
        let session = create_test_session();
        assert_eq!(session.last_activity_display(), "Just now");
    }

    #[test]
    fn test_profile_template_creation() {
        let template = ProfileTemplate {
            title: "Profile".to_string(),
            user: Some(create_test_user_context()),
            vauban: create_test_vauban_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: Some(create_test_user_context()),
            profile: create_test_profile_detail(),
            sessions: vec![create_test_session()],
            current_session_token: Some("token123".to_string()),
        };
        assert_eq!(template.title, "Profile");
        assert!(template.user.is_some());
        assert_eq!(template.profile.username, "testuser");
    }

    #[test]
    fn test_profile_template_renders() {
        let template = ProfileTemplate {
            title: "Profile".to_string(),
            user: Some(create_test_user_context()),
            vauban: create_test_vauban_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: Some(create_test_user_context()),
            profile: create_test_profile_detail(),
            sessions: Vec::new(),
            current_session_token: None,
        };
        let result = template.render();
        assert!(result.is_ok());
    }

    #[test]
    fn test_profile_detail_clone() {
        let profile = create_test_profile_detail();
        let cloned = profile.clone();
        assert_eq!(profile.uuid, cloned.uuid);
        assert_eq!(profile.email, cloned.email);
    }

    #[test]
    fn test_profile_session_clone() {
        let session = create_test_session();
        let cloned = session.clone();
        assert_eq!(session.uuid, cloned.uuid);
        assert_eq!(session.ip_address, cloned.ip_address);
    }

    // ==================== ProfileDetail Edge Cases ====================

    #[test]
    fn test_profile_detail_without_optional_fields() {
        let profile = ProfileDetail {
            uuid: "uuid-123".to_string(),
            username: "minimaluser".to_string(),
            email: "minimal@test.com".to_string(),
            first_name: None,
            last_name: None,
            phone: None,
            full_name: None,
            is_active: true,
            is_staff: false,
            is_superuser: false,
            mfa_enabled: false,
            mfa_enforced: false,
            auth_source: "local".to_string(),
            last_login: None,
            created_at: "2026-01-01 00:00:00".to_string(),
            updated_at: "2026-01-01 00:00:00".to_string(),
        };

        assert!(profile.first_name.is_none());
        assert!(profile.last_login.is_none());
        assert!(profile.full_name.is_none());
    }

    #[test]
    fn test_profile_detail_superuser() {
        let mut profile = create_test_profile_detail();
        profile.is_superuser = true;
        profile.is_staff = true;

        assert!(profile.is_superuser);
        assert!(profile.is_staff);
    }

    #[test]
    fn test_profile_detail_mfa_enforced() {
        let mut profile = create_test_profile_detail();
        profile.mfa_enabled = true;
        profile.mfa_enforced = true;

        assert!(profile.mfa_enabled);
        assert!(profile.mfa_enforced);
    }

    #[test]
    fn test_profile_detail_inactive_user() {
        let mut profile = create_test_profile_detail();
        profile.is_active = false;

        assert!(!profile.is_active);
    }

    #[test]
    fn test_profile_detail_ldap_auth_source() {
        let mut profile = create_test_profile_detail();
        profile.auth_source = "ldap".to_string();

        assert_eq!(profile.auth_source, "ldap");
    }

    #[test]
    fn test_profile_detail_debug() {
        let profile = create_test_profile_detail();
        let debug_str = format!("{:?}", profile);

        assert!(debug_str.contains("ProfileDetail"));
        assert!(debug_str.contains("testuser"));
    }

    // ==================== ProfileSession Time Display Tests ====================

    #[test]
    fn test_profile_session_age_display_minutes() {
        let mut session = create_test_session();
        session.created_at = Utc::now() - chrono::Duration::minutes(45);

        let display = session.age_display();
        assert!(
            display.contains("minutes ago"),
            "Expected 'X minutes ago', got: {}",
            display
        );
    }

    #[test]
    fn test_profile_session_age_display_hours() {
        let mut session = create_test_session();
        session.created_at = Utc::now() - chrono::Duration::hours(5);

        let display = session.age_display();
        assert!(
            display.contains("hours ago"),
            "Expected 'X hours ago', got: {}",
            display
        );
    }

    #[test]
    fn test_profile_session_age_display_days() {
        let mut session = create_test_session();
        session.created_at = Utc::now() - chrono::Duration::days(3);

        let display = session.age_display();
        assert!(
            display.contains("days ago"),
            "Expected 'X days ago', got: {}",
            display
        );
    }

    #[test]
    fn test_profile_session_last_activity_display_minutes() {
        let mut session = create_test_session();
        session.last_activity = Utc::now() - chrono::Duration::minutes(15);

        let display = session.last_activity_display();
        assert!(
            display.contains("minutes ago"),
            "Expected 'X minutes ago', got: {}",
            display
        );
    }

    #[test]
    fn test_profile_session_last_activity_display_hours() {
        let mut session = create_test_session();
        session.last_activity = Utc::now() - chrono::Duration::hours(2);

        let display = session.last_activity_display();
        assert!(
            display.contains("hours ago"),
            "Expected 'X hours ago', got: {}",
            display
        );
    }

    #[test]
    fn test_profile_session_last_activity_display_days() {
        let mut session = create_test_session();
        session.last_activity = Utc::now() - chrono::Duration::days(7);

        let display = session.last_activity_display();
        assert!(
            display.contains("days ago"),
            "Expected 'X days ago', got: {}",
            display
        );
    }

    // ==================== ProfileSession Additional Tests ====================

    #[test]
    fn test_profile_session_not_current() {
        let mut session = create_test_session();
        session.is_current = false;

        assert!(!session.is_current);
    }

    #[test]
    fn test_profile_session_debug() {
        let session = create_test_session();
        let debug_str = format!("{:?}", session);

        assert!(debug_str.contains("ProfileSession"));
        assert!(debug_str.contains("Chrome on macOS"));
    }

    #[test]
    fn test_profile_session_ipv6() {
        let mut session = create_test_session();
        session.ip_address = "::1".to_string();

        assert_eq!(session.ip_address, "::1");
    }

    // ==================== ProfileTemplate Render Tests ====================

    #[test]
    fn test_profile_template_renders_with_mfa_enabled() {
        let mut profile = create_test_profile_detail();
        profile.mfa_enabled = true;

        let template = ProfileTemplate {
            title: "Profile".to_string(),
            user: Some(create_test_user_context()),
            vauban: create_test_vauban_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: Some(create_test_user_context()),
            profile,
            sessions: Vec::new(),
            current_session_token: None,
        };

        let result = template.render();
        assert!(result.is_ok());

        let html = unwrap_ok!(result);
        assert!(
            html.contains("Active") || html.contains("Enabled"),
            "Should show MFA enabled status"
        );
    }

    #[test]
    fn test_profile_template_renders_with_multiple_sessions() {
        let sessions = vec![
            ProfileSession {
                uuid: "session-1".to_string(),
                ip_address: "192.168.1.1".to_string(),
                device_info: "Chrome on macOS".to_string(),
                last_activity: Utc::now(),
                created_at: Utc::now(),
                is_current: true,
            },
            ProfileSession {
                uuid: "session-2".to_string(),
                ip_address: "10.0.0.1".to_string(),
                device_info: "Firefox on Windows".to_string(),
                last_activity: Utc::now() - chrono::Duration::hours(1),
                created_at: Utc::now() - chrono::Duration::days(1),
                is_current: false,
            },
        ];

        let template = ProfileTemplate {
            title: "Profile".to_string(),
            user: Some(create_test_user_context()),
            vauban: create_test_vauban_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: Some(create_test_user_context()),
            profile: create_test_profile_detail(),
            sessions,
            current_session_token: Some("token123".to_string()),
        };

        let result = template.render();
        assert!(result.is_ok());

        let html = unwrap_ok!(result);
        assert!(html.contains("Chrome on macOS"));
        assert!(html.contains("Firefox on Windows"));
        assert!(html.contains("Current"));
    }

    #[test]
    fn test_profile_template_renders_superuser_badges() {
        let mut profile = create_test_profile_detail();
        profile.is_superuser = true;
        profile.is_staff = true;

        let template = ProfileTemplate {
            title: "Profile".to_string(),
            user: Some(create_test_user_context()),
            vauban: create_test_vauban_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: Some(create_test_user_context()),
            profile,
            sessions: Vec::new(),
            current_session_token: None,
        };

        let result = template.render();
        assert!(result.is_ok());

        let html = unwrap_ok!(result);
        assert!(html.contains("Admin"), "Should show Admin badge");
        assert!(html.contains("Staff"), "Should show Staff badge");
    }

    #[test]
    fn test_profile_template_renders_ldap_user() {
        let mut profile = create_test_profile_detail();
        profile.auth_source = "ldap".to_string();

        let template = ProfileTemplate {
            title: "Profile".to_string(),
            user: Some(create_test_user_context()),
            vauban: create_test_vauban_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: Some(create_test_user_context()),
            profile,
            sessions: Vec::new(),
            current_session_token: None,
        };

        let result = template.render();
        assert!(result.is_ok());

        let html = unwrap_ok!(result);
        assert!(html.contains("LDAP"), "Should show LDAP auth source");
    }

    #[test]
    fn test_profile_template_renders_without_full_name() {
        let mut profile = create_test_profile_detail();
        profile.first_name = None;
        profile.last_name = None;
        profile.full_name = None;

        let template = ProfileTemplate {
            title: "Profile".to_string(),
            user: Some(create_test_user_context()),
            vauban: create_test_vauban_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: Some(create_test_user_context()),
            profile,
            sessions: Vec::new(),
            current_session_token: None,
        };

        let result = template.render();
        assert!(result.is_ok());

        let html = unwrap_ok!(result);
        // Should fall back to username
        assert!(html.contains("testuser"));
    }

    #[test]
    fn test_profile_template_renders_mfa_enforced_warning() {
        let mut profile = create_test_profile_detail();
        profile.mfa_enforced = true;
        profile.mfa_enabled = false;

        let template = ProfileTemplate {
            title: "Profile".to_string(),
            user: Some(create_test_user_context()),
            vauban: create_test_vauban_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: Some(create_test_user_context()),
            profile,
            sessions: Vec::new(),
            current_session_token: None,
        };

        let result = template.render();
        assert!(result.is_ok());

        let html = unwrap_ok!(result);
        assert!(
            html.contains("required") || html.contains("MFA"),
            "Should show MFA requirement"
        );
    }
}
