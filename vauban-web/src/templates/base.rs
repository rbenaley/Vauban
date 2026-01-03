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

use crate::templates::partials::{SidebarTemplate, HeaderTemplate, SidebarContentTemplate};

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
    pub header_user: Option<UserContext>, // Header user for include
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
                // Superusers can view all sections
                can_view_groups: u.is_superuser || u.is_staff,
                can_view_access_rules: u.is_superuser || u.is_staff,
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
            self.sidebar_content = Some(SidebarContentTemplate {
                user: user.clone(),
                is_dashboard: path == "/",
                is_assets: path.starts_with("/assets") && !path.contains("/access"),
                is_sessions: path.contains("/sessions") && !path.contains("/recordings") && !path.contains("/approvals"),
                is_recordings: path.contains("/recordings"),
                is_users: path.contains("/users") && !path.contains("/groups"),
                is_groups: path.contains("/groups"),
                is_approvals: path.contains("/approvals"),
                is_access_rules: path.contains("/access"),
                // Superusers can view all sections
                can_view_groups: user.is_superuser || user.is_staff,
                can_view_access_rules: user.is_superuser || user.is_staff,
            });
        }
        self
    }

    /// Decompose BaseTemplate into individual fields for child templates.
    pub fn into_fields(self) -> (String, Option<UserContext>, VaubanConfig, Vec<FlashMessage>, String, Option<SidebarContentTemplate>, Option<UserContext>) {
        (self.title, self.user, self.vauban, self.messages, self.language_code, self.sidebar_content, self.header_user)
    }
}

