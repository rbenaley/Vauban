/// VAUBAN Web - Access rule edit template.
use askama::Template;

use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};

use super::access_rule_create::GroupOption;

/// Pre-populated access rule data for editing.
#[derive(Debug, Clone)]
pub struct AccessRuleEdit {
    pub uuid: String,
    pub name: String,
    pub description: String,
    pub user_group_id: i32,
    pub asset_group_id: i32,
    pub allowed_ssh: bool,
    pub allowed_rdp: bool,
    pub valid_from: String,
    pub valid_until: String,
    pub require_mfa: bool,
    pub require_approval: bool,
    pub duration_value: Option<i32>,
    pub duration_unit: String,
    pub is_active: bool,
    pub priority: String,
}

#[derive(Template)]
#[template(path = "assets/access_rule_edit.html")]
pub struct AccessRuleEditTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub rule: AccessRuleEdit,
    pub user_groups: Vec<GroupOption>,
    pub asset_groups: Vec<GroupOption>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_rule() -> AccessRuleEdit {
        AccessRuleEdit {
            uuid: "test-uuid".to_string(),
            name: "Test Rule".to_string(),
            description: "A test rule".to_string(),
            user_group_id: 1,
            asset_group_id: 2,
            allowed_ssh: true,
            allowed_rdp: false,
            valid_from: String::new(),
            valid_until: String::new(),
            require_mfa: false,
            require_approval: false,
            duration_value: Some(2),
            duration_unit: "hours".to_string(),
            is_active: true,
            priority: "0".to_string(),
        }
    }

    #[test]
    fn test_access_rule_edit_creation() {
        let rule = create_test_rule();
        assert_eq!(rule.name, "Test Rule");
        assert!(rule.allowed_ssh);
        assert!(!rule.allowed_rdp);
    }

    #[test]
    fn test_access_rule_edit_template_renders() {
        let template = AccessRuleEditTemplate {
            title: "Edit Access Rule".to_string(),
            user: Some(UserContext {
                uuid: "test".to_string(),
                username: "admin".to_string(),
                display_name: "Admin".to_string(),
                is_superuser: true,
                is_staff: true,
            }),
            vauban: VaubanConfig {
                brand_name: "VAUBAN".to_string(),
                brand_logo: None,
                theme: "dark".to_string(),
            },
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
            rule: create_test_rule(),
            user_groups: vec![GroupOption {
                id: 1,
                name: "Users".to_string(),
            }],
            asset_groups: vec![GroupOption {
                id: 2,
                name: "Servers".to_string(),
            }],
        };
        let result = template.render();
        assert!(result.is_ok(), "AccessRuleEditTemplate should render");
    }
}
