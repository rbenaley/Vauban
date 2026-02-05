//! SSH Terminal template.
//!
//! Renders a full-page terminal interface using xterm.js for SSH sessions.

use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};
use askama::Template;

/// Template for the SSH terminal page.
#[derive(Template)]
#[template(path = "sessions/terminal.html")]
pub struct TerminalTemplate {
    /// Page title.
    pub title: String,
    /// Current authenticated user.
    pub user: Option<UserContext>,
    /// Vauban brand configuration.
    pub vauban: VaubanConfig,
    /// Flash messages.
    pub messages: Vec<FlashMessage>,
    /// Language code for i18n.
    pub language_code: String,
    /// Sidebar navigation content.
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    /// User context for header.
    pub header_user: Option<UserContext>,
    /// SSH session UUID.
    pub session_id: String,
    /// WebSocket URL for terminal communication.
    pub websocket_url: String,
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

    #[test]
    fn test_terminal_template_creation() {
        let template = TerminalTemplate {
            title: "SSH Terminal".to_string(),
            user: None,
            vauban: create_test_vauban_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
            session_id: "test-session-123".to_string(),
            websocket_url: "ws://localhost/ws/terminal/test-session-123".to_string(),
        };

        assert_eq!(template.title, "SSH Terminal");
        assert_eq!(template.session_id, "test-session-123");
    }

    #[test]
    fn test_terminal_template_with_user() {
        let user = UserContext {
            uuid: "user-123".to_string(),
            username: "testuser".to_string(),
            display_name: "Test User".to_string(),
            is_superuser: false,
            is_staff: false,
        };

        let template = TerminalTemplate {
            title: "SSH Terminal".to_string(),
            user: Some(user.clone()),
            vauban: create_test_vauban_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: Some(user),
            session_id: "session-456".to_string(),
            websocket_url: String::new(),
        };

        assert!(template.user.is_some());
        assert_eq!(template.user.as_ref().map(|u| u.username.as_str()), Some("testuser"));
    }

    #[test]
    fn test_terminal_template_session_id() {
        let session_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";

        let template = TerminalTemplate {
            title: "Terminal".to_string(),
            user: None,
            vauban: create_test_vauban_config(),
            messages: Vec::new(),
            language_code: "fr".to_string(),
            sidebar_content: None,
            header_user: None,
            session_id: session_id.to_string(),
            websocket_url: format!("wss://example.com/ws/terminal/{}", session_id),
        };

        assert_eq!(template.session_id, session_id);
        assert!(template.websocket_url.contains(session_id));
    }
}
