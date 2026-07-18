/// VAUBAN Web - Secret group page templates.
use askama::Template;

use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};

/// One row of the secret-group list.
#[derive(Debug, Clone)]
pub struct SecretGroupItem {
    pub uuid: String,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub member_count: i64,
    pub created_at: String,
}

#[derive(Template)]
#[template(path = "secrets/group_list.html")]
pub struct SecretGroupListTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub groups: Vec<SecretGroupItem>,
    pub search: Option<String>,
    pub pagination: Option<crate::templates::accounts::user_list::Pagination>,
}

/// Form data for secret-group create/edit.
#[derive(Debug, Default, Clone)]
pub struct SecretGroupForm {
    pub name: String,
    pub slug: String,
    pub description: String,
}

#[derive(Template)]
#[template(path = "secrets/group_create.html")]
pub struct SecretGroupCreateTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub form: SecretGroupForm,
}

/// A secret attached to a group (detail page membership table).
#[derive(Debug, Clone)]
pub struct GroupSecretItem {
    pub uuid: String,
    pub name: String,
    pub version: i32,
    pub is_active: bool,
}

/// A secret available for attachment (add dropdown).
#[derive(Debug, Clone)]
pub struct SecretOption {
    pub uuid: String,
    pub name: String,
}

/// Detail page data for one secret group.
#[derive(Debug, Clone)]
pub struct SecretGroupDetailData {
    pub uuid: String,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub secrets: Vec<GroupSecretItem>,
    pub available_secrets: Vec<SecretOption>,
}

#[derive(Template)]
#[template(path = "secrets/group_detail.html")]
pub struct SecretGroupDetailTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub group: SecretGroupDetailData,
}

/// Edit page data for one secret group.
#[derive(Debug, Clone)]
pub struct SecretGroupEditData {
    pub uuid: String,
    pub name: String,
    pub slug: String,
    pub description: String,
}

#[derive(Template)]
#[template(path = "secrets/group_edit.html")]
pub struct SecretGroupEditTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub group: SecretGroupEditData,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_group_list_template_renders() {
        let template = SecretGroupListTemplate {
            title: "Secret Groups".to_string(),
            user: None,
            vauban: VaubanConfig {
                brand_name: "VAUBAN".to_string(),
                brand_logo: None,
                theme: "dark".to_string(),
                ..Default::default()
            },
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
            groups: vec![SecretGroupItem {
                uuid: "g1".to_string(),
                name: "Prod credentials".to_string(),
                slug: "prod-credentials".to_string(),
                description: None,
                member_count: 3,
                created_at: "2026-07-11 10:00 UTC".to_string(),
            }],
            search: None,
            pagination: None,
        };
        let html = template.render().expect("render");
        assert!(html.contains("Prod credentials"));
        assert!(html.contains("/vault/secrets/groups/g1"));
    }

    #[test]
    fn test_secret_group_detail_template_renders_membership() {
        let template = SecretGroupDetailTemplate {
            title: "Prod credentials".to_string(),
            user: None,
            vauban: VaubanConfig {
                brand_name: "VAUBAN".to_string(),
                brand_logo: None,
                theme: "dark".to_string(),
                ..Default::default()
            },
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
            group: SecretGroupDetailData {
                uuid: "g1".to_string(),
                name: "Prod credentials".to_string(),
                slug: "prod-credentials".to_string(),
                description: Some("desc".to_string()),
                created_at: "2026-07-11 10:00 UTC".to_string(),
                updated_at: "2026-07-11 10:00 UTC".to_string(),
                secrets: vec![GroupSecretItem {
                    uuid: "s1".to_string(),
                    name: "db-password".to_string(),
                    version: 1,
                    is_active: true,
                }],
                available_secrets: vec![SecretOption {
                    uuid: "s2".to_string(),
                    name: "api-token".to_string(),
                }],
            },
        };
        let html = template.render().expect("render");
        assert!(html.contains("db-password"));
        assert!(html.contains("api-token"));
    }
}
