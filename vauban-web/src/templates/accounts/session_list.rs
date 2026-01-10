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
}
