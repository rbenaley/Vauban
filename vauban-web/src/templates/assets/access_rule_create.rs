/// VAUBAN Web - Access rule create template.
use askama::Template;

use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};

/// Select option for user groups and asset groups dropdowns.
///
/// `is_virtual` is set to `true` only for the singleton "All assets" virtual
/// asset group. The template uses it to render a "Virtual" badge so the
/// operator distinguishes it from a regular static group, and to surface a
/// dynamic asset count.
#[derive(Debug, Clone)]
pub struct GroupOption {
    pub id: i32,
    pub name: String,
    pub is_virtual: bool,
    /// Optional dynamic asset count, only populated for virtual asset
    /// groups (where membership is resolved at decision time, not stored).
    pub virtual_asset_count: Option<i64>,
}

/// Form data for access rule creation (pre-populated on validation error).
#[derive(Debug, Clone)]
pub struct AccessRuleCreateForm {
    pub name: String,
    pub description: String,
    pub user_group_id: String,
    pub asset_group_id: String,
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

impl Default for AccessRuleCreateForm {
    fn default() -> Self {
        let (val, unit) =
            crate::utils::duration_to_value_unit(Some(crate::utils::DEFAULT_DURATION_SECONDS));
        Self {
            name: String::new(),
            description: String::new(),
            user_group_id: String::new(),
            asset_group_id: String::new(),
            allowed_ssh: false,
            allowed_rdp: false,
            valid_from: String::new(),
            valid_until: String::new(),
            require_mfa: false,
            require_approval: false,
            duration_value: val,
            duration_unit: unit.to_string(),
            is_active: false,
            priority: String::new(),
        }
    }
}

#[derive(Template)]
#[template(path = "assets/access_rule_create.html")]
pub struct AccessRuleCreateTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub form: AccessRuleCreateForm,
    pub user_groups: Vec<GroupOption>,
    pub asset_groups: Vec<GroupOption>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_access_rule_create_form_default() {
        let form = AccessRuleCreateForm::default();
        assert!(form.name.is_empty());
        assert!(!form.allowed_ssh);
        assert_eq!(form.duration_value, Some(2));
        assert_eq!(form.duration_unit, "hours");
    }

    #[test]
    fn test_group_option_creation() {
        let opt = GroupOption {
            id: 1,
            name: "Test Group".to_string(),
            is_virtual: false,
            virtual_asset_count: None,
        };
        assert_eq!(opt.id, 1);
        assert_eq!(opt.name, "Test Group");
        assert!(!opt.is_virtual);
        assert!(opt.virtual_asset_count.is_none());
    }

    #[test]
    fn test_group_option_virtual() {
        let opt = GroupOption {
            id: 99,
            name: "All assets".to_string(),
            is_virtual: true,
            virtual_asset_count: Some(42),
        };
        assert!(opt.is_virtual);
        assert_eq!(opt.virtual_asset_count, Some(42));
    }

    #[test]
    fn test_access_rule_create_template_renders() {
        let template = AccessRuleCreateTemplate {
            title: "New Access Rule".to_string(),
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
                ..Default::default()
            },
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
            form: AccessRuleCreateForm::default(),
            user_groups: vec![GroupOption {
                id: 1,
                name: "Users".to_string(),
                is_virtual: false,
                virtual_asset_count: None,
            }],
            asset_groups: vec![GroupOption {
                id: 1,
                name: "Servers".to_string(),
                is_virtual: false,
                virtual_asset_count: None,
            }],
        };
        let html = template
            .render()
            .expect("AccessRuleCreateTemplate should render");
        assert!(
            html.contains("duration_value"),
            "should have duration_value input"
        );
        assert!(
            html.contains("duration_unit"),
            "should have duration_unit select"
        );
        assert!(html.contains("value=\"2\""), "should default to 2 hours");
    }
}
