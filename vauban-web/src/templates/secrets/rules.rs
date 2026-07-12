/// VAUBAN Web - Secret access rule page templates.
///
/// Rules are TRIPLES: a user group (`vauban_groups`) x a secret group x
/// a provenance asset group (`asset_groups`). No protocols, no MFA, no
/// JIT: only a validity window, an active flag and a priority — the
/// consumer is an M2M API key calling from an identity-verified asset.
use askama::Template;

use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};

/// Select option for the rule editor dropdowns. `is_virtual` is `true`
/// only for the singleton virtual groups ("All secrets" / "All assets").
#[derive(Debug, Clone)]
pub struct SecretGroupOption {
    pub id: i32,
    pub name: String,
    pub is_virtual: bool,
}

/// One row of the secret-access-rule list.
#[derive(Debug, Clone)]
pub struct SecretRuleItem {
    pub uuid: String,
    pub name: String,
    pub user_group_name: String,
    pub secret_group_name: String,
    pub asset_group_name: String,
    pub is_active: bool,
    /// Eclipse lint: `true` when another ACTIVE rule with the same user
    /// group, a covering secret group and the virtual "All assets"
    /// provenance makes this rule's asset-group restriction moot.
    pub is_eclipsed: bool,
}

#[derive(Template)]
#[template(path = "secrets/rule_list.html")]
pub struct SecretRuleListTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub rules: Vec<SecretRuleItem>,
}

/// Form data for rule creation (re-populated on validation error).
#[derive(Debug, Default, Clone)]
pub struct SecretRuleForm {
    pub name: String,
    pub description: String,
    pub user_group_id: String,
    pub secret_group_id: String,
    pub asset_group_id: String,
    pub valid_from: String,
    pub valid_until: String,
    pub is_active: bool,
    pub priority: String,
}

#[derive(Template)]
#[template(path = "secrets/rule_create.html")]
pub struct SecretRuleCreateTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub form: SecretRuleForm,
    pub user_groups: Vec<SecretGroupOption>,
    pub secret_groups: Vec<SecretGroupOption>,
    pub asset_groups: Vec<SecretGroupOption>,
}

/// Detail page data for one rule.
#[derive(Debug, Clone)]
pub struct SecretRuleDetailData {
    pub uuid: String,
    pub name: String,
    pub description: Option<String>,
    pub user_group_name: String,
    pub secret_group_name: String,
    pub asset_group_name: String,
    /// `true` when the provenance group is the virtual "All assets"
    /// singleton (any known, identity-verified asset).
    pub asset_group_is_virtual: bool,
    pub valid_from: Option<String>,
    pub valid_until: Option<String>,
    pub is_active: bool,
    pub priority: i32,
    /// Eclipse lint (see [`SecretRuleItem::is_eclipsed`]): drives the
    /// amber callout on the detail page.
    pub is_eclipsed: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Template)]
#[template(path = "secrets/rule_detail.html")]
pub struct SecretRuleDetailTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub rule: SecretRuleDetailData,
}

/// Edit page data for one rule.
#[derive(Debug, Clone)]
pub struct SecretRuleEditData {
    pub uuid: String,
    pub name: String,
    pub description: String,
    pub user_group_id: i32,
    pub secret_group_id: i32,
    pub asset_group_id: i32,
    pub valid_from: String,
    pub valid_until: String,
    pub is_active: bool,
    pub priority: String,
}

#[derive(Template)]
#[template(path = "secrets/rule_edit.html")]
pub struct SecretRuleEditTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub rule: SecretRuleEditData,
    pub user_groups: Vec<SecretGroupOption>,
    pub secret_groups: Vec<SecretGroupOption>,
    pub asset_groups: Vec<SecretGroupOption>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_rule_create_template_renders_virtual_badge() {
        let template = SecretRuleCreateTemplate {
            title: "New Secret Access Rule".to_string(),
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
            form: SecretRuleForm::default(),
            user_groups: vec![SecretGroupOption {
                id: 1,
                name: "Ops".to_string(),
                is_virtual: false,
            }],
            secret_groups: vec![SecretGroupOption {
                id: 9,
                name: "All secrets".to_string(),
                is_virtual: true,
            }],
            asset_groups: vec![SecretGroupOption {
                id: 4,
                name: "All assets".to_string(),
                is_virtual: true,
            }],
        };
        let html = template.render().expect("render");
        assert!(html.contains("All secrets"));
        assert!(html.contains("Virtual"));
        assert!(html.contains("All assets"));
        assert!(html.contains("any known asset"));
    }

    #[test]
    fn test_secret_rule_list_template_renders() {
        let template = SecretRuleListTemplate {
            title: "Secret Access Rules".to_string(),
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
            rules: vec![SecretRuleItem {
                uuid: "r1".to_string(),
                name: "Ops reads prod".to_string(),
                user_group_name: "Ops".to_string(),
                secret_group_name: "Prod credentials".to_string(),
                asset_group_name: "Prod servers".to_string(),
                is_active: true,
                is_eclipsed: false,
            }],
        };
        let html = template.render().expect("render");
        assert!(html.contains("Ops reads prod"));
        assert!(html.contains("/vault/secrets/access/r1"));
        assert!(html.contains("Prod servers"));
        assert!(!html.contains("Eclipsed"));
    }

    #[test]
    fn test_secret_rule_list_template_renders_eclipsed_badge() {
        let template = SecretRuleListTemplate {
            title: "Secret Access Rules".to_string(),
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
            rules: vec![SecretRuleItem {
                uuid: "r2".to_string(),
                name: "Narrow rule".to_string(),
                user_group_name: "Ops".to_string(),
                secret_group_name: "Prod credentials".to_string(),
                asset_group_name: "One box".to_string(),
                is_active: true,
                is_eclipsed: true,
            }],
        };
        let html = template.render().expect("render");
        assert!(html.contains("Eclipsed"));
    }
}
