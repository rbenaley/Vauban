/// VAUBAN Web - API key list template.
use askama::Template;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};

/// API key item for display in the template.
#[derive(Debug, Clone)]
pub struct ApiKeyItem {
    pub uuid: Uuid,
    pub name: String,
    pub key_prefix: String,
    pub scopes: Vec<String>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

impl ApiKeyItem {
    /// Get a human-readable description of last use.
    pub fn last_used_display(&self) -> String {
        match self.last_used_at {
            Some(dt) => {
                let duration = Utc::now().signed_duration_since(dt);
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
            None => "Never used".to_string(),
        }
    }

    /// Get expiration status display.
    pub fn expires_display(&self) -> String {
        match self.expires_at {
            Some(dt) if dt < Utc::now() => "Expired".to_string(),
            Some(dt) => {
                let duration = dt.signed_duration_since(Utc::now());
                if duration.num_days() > 30 {
                    format!("Expires in {} months", duration.num_days() / 30)
                } else if duration.num_days() > 0 {
                    format!("Expires in {} days", duration.num_days())
                } else if duration.num_hours() > 0 {
                    format!("Expires in {} hours", duration.num_hours())
                } else {
                    "Expires soon".to_string()
                }
            }
            None => "Never expires".to_string(),
        }
    }

    /// Check if the key has expired.
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            expires_at < Utc::now()
        } else {
            false
        }
    }

    /// Get scopes as a comma-separated string.
    pub fn scopes_display(&self) -> String {
        self.scopes.join(", ")
    }
}

#[derive(Template)]
#[template(path = "accounts/apikey_list.html")]
pub struct ApikeyListTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub api_keys: Vec<ApiKeyItem>,
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

    fn create_test_api_key() -> ApiKeyItem {
        ApiKeyItem {
            uuid: Uuid::new_v4(),
            name: "Test Key".to_string(),
            key_prefix: "vbn_abcd".to_string(),
            scopes: vec!["read".to_string(), "write".to_string()],
            last_used_at: None,
            expires_at: None,
            is_active: true,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn test_apikey_list_template_creation() {
        let template = ApikeyListTemplate {
            title: "API Keys".to_string(),
            user: None,
            vauban: create_test_vauban_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
            api_keys: Vec::new(),
        };
        assert_eq!(template.title, "API Keys");
        assert!(template.user.is_none());
    }

    #[test]
    fn test_apikey_list_template_with_keys() {
        let template = ApikeyListTemplate {
            title: "API Keys".to_string(),
            user: None,
            vauban: create_test_vauban_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
            api_keys: vec![create_test_api_key()],
        };
        assert_eq!(template.api_keys.len(), 1);
    }

    #[test]
    fn test_apikey_list_template_with_messages() {
        let template = ApikeyListTemplate {
            title: "API Keys".to_string(),
            user: None,
            vauban: create_test_vauban_config(),
            messages: vec![FlashMessage {
                level: "success".to_string(),
                message: "Key created".to_string(),
            }],
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
            api_keys: Vec::new(),
        };
        assert_eq!(template.messages.len(), 1);
    }

    #[test]
    fn test_apikey_list_template_renders() {
        let template = ApikeyListTemplate {
            title: "API Keys".to_string(),
            user: None,
            vauban: create_test_vauban_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
            api_keys: Vec::new(),
        };
        let result = template.render();
        assert!(result.is_ok());
    }

    #[test]
    fn test_api_key_item_last_used_display_never() {
        let key = create_test_api_key();
        assert_eq!(key.last_used_display(), "Never used");
    }

    #[test]
    fn test_api_key_item_expires_display_never() {
        let key = create_test_api_key();
        assert_eq!(key.expires_display(), "Never expires");
    }

    #[test]
    fn test_api_key_item_scopes_display() {
        let key = create_test_api_key();
        assert_eq!(key.scopes_display(), "read, write");
    }

    #[test]
    fn test_api_key_item_is_expired() {
        let key = create_test_api_key();
        assert!(!key.is_expired());
    }
}
