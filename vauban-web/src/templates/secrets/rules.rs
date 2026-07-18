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
    pub pagination: Option<crate::templates::accounts::user_list::Pagination>,
    pub search: Option<String>,
    pub user_group_filter: Option<String>,
    pub secret_group_filter: Option<String>,
    pub asset_group_filter: Option<String>,
    pub status_filter: Option<String>,
    pub eclipsed_filter: Option<String>,
    /// Distinct option values for the three group selects, derived
    /// from the full (unfiltered) rule set.
    pub user_groups: Vec<String>,
    pub secret_groups: Vec<String>,
    pub asset_groups: Vec<String>,
}

impl SecretRuleListTemplate {
    /// True when at least one live filter narrows the list; drives the
    /// double-branch empty state ("no matching" vs "none configured").
    #[must_use]
    pub fn has_filters(&self) -> bool {
        self.search.is_some()
            || self.user_group_filter.is_some()
            || self.secret_group_filter.is_some()
            || self.asset_group_filter.is_some()
            || self.status_filter.is_some()
            || self.eclipsed_filter.is_some()
    }

    /// `&key=value` query-string suffix carrying every active filter,
    /// percent-encoded, appended to the pagination links so switching
    /// page never drops the filters. With six filterable params the
    /// inline `{% if %}` idiom used by two-filter templates becomes
    /// unreadable; Askama HTML-escapes the returned `&` to `&amp;`,
    /// which is the correct form inside an href attribute.
    #[must_use]
    pub fn filter_query_suffix(&self) -> String {
        crate::services::list_filters::query_suffix(&[
            ("search", &self.search),
            ("user_group", &self.user_group_filter),
            ("secret_group", &self.secret_group_filter),
            ("asset_group", &self.asset_group_filter),
            ("status", &self.status_filter),
            ("eclipsed", &self.eclipsed_filter),
        ])
    }
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
            pagination: None,
            search: None,
            user_group_filter: None,
            secret_group_filter: None,
            asset_group_filter: None,
            status_filter: None,
            eclipsed_filter: None,
            user_groups: vec!["Ops".to_string()],
            secret_groups: vec!["Prod credentials".to_string()],
            asset_groups: vec!["Prod servers".to_string()],
        };
        let html = template.render().expect("render");
        assert!(html.contains("Ops reads prod"));
        assert!(html.contains("/vault/secrets/access/r1"));
        assert!(html.contains("Prod servers"));
        // The toolbar always carries the "Eclipsed" filter label; only
        // the BADGE must be absent for a non-eclipsed rule.
        assert!(!html.contains(">Eclipsed</span>"));
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
            pagination: None,
            search: None,
            user_group_filter: None,
            secret_group_filter: None,
            asset_group_filter: None,
            status_filter: None,
            eclipsed_filter: None,
            user_groups: Vec::new(),
            secret_groups: Vec::new(),
            asset_groups: Vec::new(),
        };
        let html = template.render().expect("render");
        assert!(html.contains(">Eclipsed</span>"));
    }
}
