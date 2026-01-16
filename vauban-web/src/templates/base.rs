/// VAUBAN Web - Base template.
///
/// Base template struct for Askama that wraps all page templates.
use askama::Template;

/// Flash message for displaying notifications.
#[derive(Debug, Clone)]
pub struct FlashMessage {
    pub level: String, // "success", "error", "warning", "info"
    pub message: String,
}

/// Vauban configuration for templates.
#[derive(Debug, Clone)]
pub struct VaubanConfig {
    pub brand_name: String,
    pub brand_logo: Option<String>,
    pub theme: String, // "light" or "dark"
}

use crate::templates::partials::SidebarContentTemplate;

/// Base template that all pages extend.
#[derive(Template)]
#[template(path = "base.html")]
pub struct BaseTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content: Option<SidebarContentTemplate>, // Sidebar content for include
    pub header_user: Option<UserContext>,                // Header user for include
}

/// User context for templates (simplified from AuthUser).
#[derive(Debug, Clone)]
pub struct UserContext {
    pub uuid: String,
    pub username: String,
    pub display_name: String,
    pub is_superuser: bool,
    pub is_staff: bool,
}

impl UserContext {
    pub fn is_authenticated(&self) -> bool {
        true
    }
}

impl BaseTemplate {
    pub fn new(title: String, user: Option<UserContext>) -> Self {
        let header_user = user.clone();
        let sidebar_content = user.as_ref().map(|u| {
            let is_admin = u.is_superuser || u.is_staff;
            SidebarContentTemplate {
                user: u.clone(),
                is_dashboard: false,
                is_assets: false,
                is_sessions: false,
                is_recordings: false,
                is_users: false,
                is_groups: false,
                is_approvals: false,
                is_access_rules: false,
                // Superusers and staff can view all sections
                can_view_groups: is_admin,
                can_view_access_rules: is_admin,
                can_view_admin: is_admin,
            }
        });

        Self {
            title,
            user,
            vauban: VaubanConfig {
                brand_name: "VAUBAN".to_string(),
                brand_logo: None,
                theme: "dark".to_string(),
            },
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content,
            header_user,
        }
    }

    pub fn with_messages(mut self, messages: Vec<FlashMessage>) -> Self {
        self.messages = messages;
        self
    }

    pub fn with_current_path(mut self, path: &str) -> Self {
        // Update sidebar with current path if user exists
        if let Some(ref user) = self.user {
            let is_admin = user.is_superuser || user.is_staff;
            self.sidebar_content = Some(SidebarContentTemplate {
                user: user.clone(),
                is_dashboard: path == "/",
                is_assets: path.starts_with("/assets") && !path.contains("/access"),
                is_sessions: path.contains("/sessions")
                    && !path.contains("/recordings")
                    && !path.contains("/approvals"),
                is_recordings: path.contains("/recordings"),
                is_users: path.contains("/users") && !path.contains("/groups"),
                is_groups: path.contains("/groups"),
                is_approvals: path.contains("/approvals"),
                is_access_rules: path.contains("/access"),
                // Superusers and staff can view all sections
                can_view_groups: is_admin,
                can_view_access_rules: is_admin,
                can_view_admin: is_admin,
            });
        }
        self
    }

    /// Decompose BaseTemplate into individual fields for child templates.
    #[allow(clippy::type_complexity)]
    pub fn into_fields(
        self,
    ) -> (
        String,
        Option<UserContext>,
        VaubanConfig,
        Vec<FlashMessage>,
        String,
        Option<SidebarContentTemplate>,
        Option<UserContext>,
    ) {
        (
            self.title,
            self.user,
            self.vauban,
            self.messages,
            self.language_code,
            self.sidebar_content,
            self.header_user,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== FlashMessage Tests ====================

    #[test]
    fn test_flash_message_success() {
        let msg = FlashMessage {
            level: "success".to_string(),
            message: "Operation completed".to_string(),
        };

        assert_eq!(msg.level, "success");
        assert_eq!(msg.message, "Operation completed");
    }

    #[test]
    fn test_flash_message_error() {
        let msg = FlashMessage {
            level: "error".to_string(),
            message: "Something went wrong".to_string(),
        };

        assert_eq!(msg.level, "error");
    }

    #[test]
    fn test_flash_message_clone() {
        let msg = FlashMessage {
            level: "warning".to_string(),
            message: "Be careful".to_string(),
        };
        let cloned = msg.clone();

        assert_eq!(msg.level, cloned.level);
        assert_eq!(msg.message, cloned.message);
    }

    #[test]
    fn test_flash_message_debug() {
        let msg = FlashMessage {
            level: "info".to_string(),
            message: "FYI".to_string(),
        };
        let debug_str = format!("{:?}", msg);

        assert!(debug_str.contains("FlashMessage"));
        assert!(debug_str.contains("info"));
    }

    // ==================== VaubanConfig Tests ====================

    #[test]
    fn test_vauban_config_default() {
        let config = VaubanConfig {
            brand_name: "VAUBAN".to_string(),
            brand_logo: None,
            theme: "dark".to_string(),
        };

        assert_eq!(config.brand_name, "VAUBAN");
        assert!(config.brand_logo.is_none());
        assert_eq!(config.theme, "dark");
    }

    #[test]
    fn test_vauban_config_with_logo() {
        let config = VaubanConfig {
            brand_name: "Custom Brand".to_string(),
            brand_logo: Some("/static/logo.png".to_string()),
            theme: "light".to_string(),
        };

        assert_eq!(config.brand_name, "Custom Brand");
        assert_eq!(config.brand_logo, Some("/static/logo.png".to_string()));
        assert_eq!(config.theme, "light");
    }

    #[test]
    fn test_vauban_config_clone() {
        let config = VaubanConfig {
            brand_name: "Test".to_string(),
            brand_logo: Some("logo.svg".to_string()),
            theme: "dark".to_string(),
        };
        let cloned = config.clone();

        assert_eq!(config.brand_name, cloned.brand_name);
        assert_eq!(config.brand_logo, cloned.brand_logo);
    }

    // ==================== UserContext Tests ====================

    fn create_test_user() -> UserContext {
        UserContext {
            uuid: "test-uuid-123".to_string(),
            username: "testuser".to_string(),
            display_name: "Test User".to_string(),
            is_superuser: false,
            is_staff: false,
        }
    }

    #[test]
    fn test_user_context_is_authenticated() {
        let user = create_test_user();
        assert!(user.is_authenticated());
    }

    #[test]
    fn test_user_context_superuser() {
        let user = UserContext {
            uuid: "admin-uuid".to_string(),
            username: "admin".to_string(),
            display_name: "Administrator".to_string(),
            is_superuser: true,
            is_staff: true,
        };

        assert!(user.is_superuser);
        assert!(user.is_staff);
        assert!(user.is_authenticated());
    }

    #[test]
    fn test_user_context_clone() {
        let user = create_test_user();
        let cloned = user.clone();

        assert_eq!(user.uuid, cloned.uuid);
        assert_eq!(user.username, cloned.username);
        assert_eq!(user.display_name, cloned.display_name);
    }

    #[test]
    fn test_user_context_debug() {
        let user = create_test_user();
        let debug_str = format!("{:?}", user);

        assert!(debug_str.contains("UserContext"));
        assert!(debug_str.contains("testuser"));
    }

    // ==================== BaseTemplate Tests ====================

    #[test]
    fn test_base_template_new_without_user() {
        let base = BaseTemplate::new("Login".to_string(), None);

        assert_eq!(base.title, "Login");
        assert!(base.user.is_none());
        assert!(base.sidebar_content.is_none());
        assert!(base.header_user.is_none());
        assert_eq!(base.vauban.brand_name, "VAUBAN");
        assert_eq!(base.language_code, "en");
    }

    #[test]
    fn test_base_template_new_with_user() {
        let user = create_test_user();
        let base = BaseTemplate::new("Dashboard".to_string(), Some(user));

        assert_eq!(base.title, "Dashboard");
        assert!(base.user.is_some());
        assert!(base.sidebar_content.is_some());
        assert!(base.header_user.is_some());
    }

    #[test]
    fn test_base_template_with_messages() {
        let base = BaseTemplate::new("Test".to_string(), None).with_messages(vec![
            FlashMessage {
                level: "success".to_string(),
                message: "Done".to_string(),
            },
            FlashMessage {
                level: "error".to_string(),
                message: "Failed".to_string(),
            },
        ]);

        assert_eq!(base.messages.len(), 2);
        assert_eq!(base.messages[0].level, "success");
        assert_eq!(base.messages[1].level, "error");
    }

    #[test]
    fn test_base_template_with_current_path_dashboard() {
        let user = create_test_user();
        let base = BaseTemplate::new("Dashboard".to_string(), Some(user)).with_current_path("/");

        let sidebar = base.sidebar_content.unwrap();
        assert!(sidebar.is_dashboard);
        assert!(!sidebar.is_assets);
        assert!(!sidebar.is_sessions);
    }

    #[test]
    fn test_base_template_with_current_path_assets() {
        let user = create_test_user();
        let base = BaseTemplate::new("Assets".to_string(), Some(user)).with_current_path("/assets");

        let sidebar = base.sidebar_content.unwrap();
        assert!(!sidebar.is_dashboard);
        assert!(sidebar.is_assets);
    }

    #[test]
    fn test_base_template_with_current_path_sessions() {
        let user = create_test_user();
        let base =
            BaseTemplate::new("Sessions".to_string(), Some(user)).with_current_path("/sessions");

        let sidebar = base.sidebar_content.unwrap();
        assert!(sidebar.is_sessions);
        assert!(!sidebar.is_recordings);
    }

    #[test]
    fn test_base_template_with_current_path_recordings() {
        let user = create_test_user();
        let base = BaseTemplate::new("Recordings".to_string(), Some(user))
            .with_current_path("/sessions/recordings");

        let sidebar = base.sidebar_content.unwrap();
        assert!(sidebar.is_recordings);
    }

    #[test]
    fn test_base_template_superuser_can_view_all() {
        let user = UserContext {
            uuid: "admin".to_string(),
            username: "admin".to_string(),
            display_name: "Admin".to_string(),
            is_superuser: true,
            is_staff: true,
        };
        let base = BaseTemplate::new("Admin".to_string(), Some(user));

        let sidebar = base.sidebar_content.unwrap();
        assert!(sidebar.can_view_groups);
        assert!(sidebar.can_view_access_rules);
    }

    #[test]
    fn test_base_template_into_fields() {
        let user = create_test_user();
        let base = BaseTemplate::new("Test".to_string(), Some(user));
        let (title, user_ctx, vauban, messages, lang, sidebar, header) = base.into_fields();

        assert_eq!(title, "Test");
        assert!(user_ctx.is_some());
        assert_eq!(vauban.brand_name, "VAUBAN");
        assert!(messages.is_empty());
        assert_eq!(lang, "en");
        assert!(sidebar.is_some());
        assert!(header.is_some());
    }

    #[test]
    fn test_base_template_renders() {
        let base = BaseTemplate::new("Test Page".to_string(), None);
        let result = base.render();
        assert!(result.is_ok(), "BaseTemplate should render successfully");
        let html = result.unwrap();
        // Template renders successfully - content verification depends on HTML structure
        assert!(!html.is_empty(), "Rendered HTML should not be empty");
    }

    #[test]
    fn test_base_template_renders_with_user() {
        let user = create_test_user();
        let base = BaseTemplate::new("Dashboard".to_string(), Some(user));
        let result = base.render();
        assert!(result.is_ok(), "BaseTemplate with user should render");
    }
}
