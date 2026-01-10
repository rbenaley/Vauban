/// VAUBAN Web - User session list template.
use askama::Template;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};

/// Session item for display in the template.
#[derive(Debug, Clone)]
pub struct AuthSessionItem {
    pub uuid: Uuid,
    pub ip_address: String,
    pub device_info: String,
    pub last_activity: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub is_current: bool,
    pub is_expired: bool,
}

impl AuthSessionItem {
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
#[template(path = "accounts/session_list.html")]
pub struct SessionListTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub sessions: Vec<AuthSessionItem>,
}

/// Partial template for the sessions list (HTMX fragment).
/// Used for real-time updates via WebSocket to ensure each client
/// gets a personalized "Current session" indicator.
#[derive(Template)]
#[template(path = "accounts/session_list_partial.html")]
pub struct SessionListPartialTemplate {
    pub sessions: Vec<AuthSessionItem>,
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

    fn create_test_session() -> AuthSessionItem {
        AuthSessionItem {
            uuid: Uuid::new_v4(),
            ip_address: "192.168.1.1".to_string(),
            device_info: "Chrome on macOS".to_string(),
            last_activity: Utc::now(),
            created_at: Utc::now(),
            is_current: true,
            is_expired: false,
        }
    }

    #[test]
    fn test_session_list_template_creation() {
        let template = SessionListTemplate {
            title: "Sessions".to_string(),
            user: None,
            vauban: create_test_vauban_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
            sessions: Vec::new(),
        };
        assert_eq!(template.title, "Sessions");
    }

    #[test]
    fn test_session_list_template_with_sessions() {
        let template = SessionListTemplate {
            title: "Sessions".to_string(),
            user: None,
            vauban: create_test_vauban_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
            sessions: vec![create_test_session()],
        };
        assert_eq!(template.sessions.len(), 1);
    }

    #[test]
    fn test_session_list_template_renders() {
        let template = SessionListTemplate {
            title: "Sessions".to_string(),
            user: None,
            vauban: create_test_vauban_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
            sessions: Vec::new(),
        };
        let result = template.render();
        assert!(result.is_ok());
    }

    #[test]
    fn test_auth_session_item_age_display() {
        let session = create_test_session();
        assert_eq!(session.age_display(), "Just now");
    }

    #[test]
    fn test_auth_session_item_last_activity_display() {
        let session = create_test_session();
        assert_eq!(session.last_activity_display(), "Just now");
    }

    // ==================== SessionListPartialTemplate Tests ====================

    #[test]
    fn test_session_list_partial_template_empty() {
        let template = SessionListPartialTemplate {
            sessions: Vec::new(),
        };
        let result = template.render();
        assert!(result.is_ok());
        let html = result.unwrap();
        assert!(html.contains("No active sessions"));
    }

    #[test]
    fn test_session_list_partial_template_with_sessions() {
        let template = SessionListPartialTemplate {
            sessions: vec![create_test_session()],
        };
        let result = template.render();
        assert!(result.is_ok());
        let html = result.unwrap();
        assert!(html.contains("Chrome on macOS"));
        assert!(html.contains("192.168.1.1"));
    }

    #[test]
    fn test_session_list_partial_template_current_session() {
        let current_session = AuthSessionItem {
            uuid: Uuid::new_v4(),
            ip_address: "10.0.0.1".to_string(),
            device_info: "Safari on macOS".to_string(),
            last_activity: Utc::now(),
            created_at: Utc::now(),
            is_current: true,
            is_expired: false,
        };
        let template = SessionListPartialTemplate {
            sessions: vec![current_session],
        };
        let result = template.render();
        assert!(result.is_ok());
        let html = result.unwrap();
        assert!(html.contains("Current session"));
        assert!(html.contains("This device"));
        // Should NOT have a revoke button for current session
        assert!(!html.contains("Revoke</button>") || html.contains("This device"));
    }

    #[test]
    fn test_session_list_partial_template_other_session() {
        let other_session = AuthSessionItem {
            uuid: Uuid::new_v4(),
            ip_address: "192.168.1.100".to_string(),
            device_info: "Firefox on Windows".to_string(),
            last_activity: Utc::now(),
            created_at: Utc::now(),
            is_current: false,
            is_expired: false,
        };
        let template = SessionListPartialTemplate {
            sessions: vec![other_session],
        };
        let result = template.render();
        assert!(result.is_ok());
        let html = result.unwrap();
        assert!(html.contains("Firefox on Windows"));
        // Should NOT have "Current session" badge
        assert!(!html.contains("Current session"));
        // Should have revoke button
        assert!(html.contains("Revoke"));
    }

    #[test]
    fn test_session_list_partial_template_mixed_sessions() {
        let current_session = AuthSessionItem {
            uuid: Uuid::new_v4(),
            ip_address: "10.0.0.1".to_string(),
            device_info: "Safari on macOS".to_string(),
            last_activity: Utc::now(),
            created_at: Utc::now(),
            is_current: true,
            is_expired: false,
        };
        let other_session = AuthSessionItem {
            uuid: Uuid::new_v4(),
            ip_address: "192.168.1.100".to_string(),
            device_info: "Chrome on iPhone".to_string(),
            last_activity: Utc::now(),
            created_at: Utc::now(),
            is_current: false,
            is_expired: false,
        };
        let template = SessionListPartialTemplate {
            sessions: vec![current_session, other_session],
        };
        let result = template.render();
        assert!(result.is_ok());
        let html = result.unwrap();
        // Should have both sessions
        assert!(html.contains("Safari on macOS"));
        assert!(html.contains("Chrome on iPhone"));
        // Should have exactly one "Current session" badge
        assert!(html.matches("Current session").count() == 1);
    }
}
