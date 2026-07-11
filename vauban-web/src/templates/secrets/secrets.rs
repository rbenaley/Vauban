/// VAUBAN Web - Vault secret page templates.
///
/// SECURITY: the secret VALUE is write-only across the whole section.
/// None of these structs carries a value/ciphertext field, so a template
/// cannot leak it even by accident (pinned by
/// `tests/web/vault_secrets_pins_test`).
use askama::Template;

use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};

/// One row of the secret list.
#[derive(Debug, Clone)]
pub struct SecretItem {
    pub uuid: String,
    pub name: String,
    pub description: Option<String>,
    pub version: i32,
    pub is_active: bool,
    pub group_count: i64,
    pub updated_at: String,
}

#[derive(Template)]
#[template(path = "secrets/secret_list.html")]
pub struct SecretListTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub secrets: Vec<SecretItem>,
}

/// Form data for secret creation (re-populated on validation error;
/// the value itself NEVER round-trips).
#[derive(Debug, Default, Clone)]
pub struct SecretCreateForm {
    pub name: String,
    pub description: String,
    pub is_active: bool,
}

#[derive(Template)]
#[template(path = "secrets/secret_create.html")]
pub struct SecretCreateTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub form: SecretCreateForm,
}

/// Reference to a secret group carrying a secret (detail page chips).
#[derive(Debug, Clone)]
pub struct SecretGroupRef {
    pub uuid: String,
    pub name: String,
}

/// Detail page data — metadata only, never the value.
#[derive(Debug, Clone)]
pub struct SecretDetailData {
    pub uuid: String,
    pub name: String,
    pub description: Option<String>,
    pub version: i32,
    pub is_active: bool,
    pub created_at: String,
    pub updated_at: String,
    pub created_by: Option<String>,
    pub updated_by: Option<String>,
    pub groups: Vec<SecretGroupRef>,
}

#[derive(Template)]
#[template(path = "secrets/secret_detail.html")]
pub struct SecretDetailTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub secret: SecretDetailData,
}

/// Edit page data. The value field renders EMPTY: an empty submit keeps
/// the stored ciphertext, a non-empty submit re-encrypts and bumps
/// `version`.
#[derive(Debug, Clone)]
pub struct SecretEditData {
    pub uuid: String,
    pub name: String,
    pub description: String,
    pub is_active: bool,
    pub version: i32,
}

#[derive(Template)]
#[template(path = "secrets/secret_edit.html")]
pub struct SecretEditTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub secret: SecretEditData,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_fields() -> (VaubanConfig, Vec<FlashMessage>) {
        (
            VaubanConfig {
                brand_name: "VAUBAN".to_string(),
                brand_logo: None,
                theme: "dark".to_string(),
                ..Default::default()
            },
            Vec::new(),
        )
    }

    #[test]
    fn test_secret_list_template_renders() {
        let (vauban, messages) = base_fields();
        let template = SecretListTemplate {
            title: "Vault Secrets".to_string(),
            user: None,
            vauban,
            messages,
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
            secrets: vec![SecretItem {
                uuid: "u1".to_string(),
                name: "db-password".to_string(),
                description: Some("Prod".to_string()),
                version: 2,
                is_active: true,
                group_count: 1,
                updated_at: "2026-07-11 10:00 UTC".to_string(),
            }],
        };
        let html = template.render().expect("render");
        assert!(html.contains("db-password"));
        assert!(html.contains("/vault/secrets/u1"));
    }

    #[test]
    fn test_secret_detail_template_never_renders_a_value_field() {
        let (vauban, messages) = base_fields();
        let template = SecretDetailTemplate {
            title: "db-password".to_string(),
            user: None,
            vauban,
            messages,
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
            secret: SecretDetailData {
                uuid: "u1".to_string(),
                name: "db-password".to_string(),
                description: None,
                version: 1,
                is_active: true,
                created_at: "2026-07-11 10:00 UTC".to_string(),
                updated_at: "2026-07-11 10:00 UTC".to_string(),
                created_by: None,
                updated_by: None,
                groups: Vec::new(),
            },
        };
        let html = template.render().expect("render");
        // The detail page shows metadata only; the write-only posture
        // means no input or reveal affordance for the value.
        assert!(!html.contains("name=\"value\""));
    }

    #[test]
    fn test_secret_edit_template_value_field_is_empty() {
        let (vauban, messages) = base_fields();
        let template = SecretEditTemplate {
            title: "Edit".to_string(),
            user: None,
            vauban,
            messages,
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
            secret: SecretEditData {
                uuid: "u1".to_string(),
                name: "db-password".to_string(),
                description: String::new(),
                is_active: true,
                version: 3,
            },
        };
        let html = template.render().expect("render");
        // The value textarea must exist but be empty (write-only).
        assert!(html.contains("name=\"value\""));
        assert!(!html.contains("v1:"));
    }
}
