/// VAUBAN Web - Access rule detail template.
use askama::Template;

use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};

/// Access rule detail data for display.
#[derive(Debug, Clone)]
pub struct AccessRuleDetailData {
    pub uuid: String,
    pub name: String,
    pub description: Option<String>,
    pub user_group_name: String,
    pub asset_group_name: String,
    pub allowed_protocols: Vec<String>,
    pub valid_from: Option<String>,
    pub valid_until: Option<String>,
    pub require_mfa: bool,
    pub require_justification: bool,
    pub max_session_duration: Option<i32>,
    pub is_active: bool,
    pub priority: i32,
    pub created_at: String,
    pub updated_at: String,
}

impl AccessRuleDetailData {
    pub fn status_class(&self) -> &str {
        if self.is_active {
            "bg-green-100 text-green-800 dark:bg-green-900/50 dark:text-green-300"
        } else {
            "bg-red-100 text-red-800 dark:bg-red-900/50 dark:text-red-300"
        }
    }

    pub fn protocols_display(&self) -> String {
        self.allowed_protocols
            .iter()
            .map(|p| p.to_uppercase())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

#[derive(Template)]
#[template(path = "assets/access_rule_detail.html")]
pub struct AccessRuleDetailTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub rule: AccessRuleDetailData,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_rule() -> AccessRuleDetailData {
        AccessRuleDetailData {
            uuid: "test-uuid".to_string(),
            name: "Test Rule".to_string(),
            description: Some("A description".to_string()),
            user_group_name: "Dev Team".to_string(),
            asset_group_name: "Production".to_string(),
            allowed_protocols: vec!["ssh".to_string(), "rdp".to_string()],
            valid_from: None,
            valid_until: None,
            require_mfa: false,
            require_justification: false,
            max_session_duration: None,
            is_active: true,
            priority: 0,
            created_at: "2026-01-01 00:00:00".to_string(),
            updated_at: "2026-01-02 00:00:00".to_string(),
        }
    }

    #[test]
    fn test_status_class_active() {
        let rule = create_test_rule();
        assert!(rule.status_class().contains("green"));
    }

    #[test]
    fn test_status_class_inactive() {
        let mut rule = create_test_rule();
        rule.is_active = false;
        assert!(rule.status_class().contains("red"));
    }

    #[test]
    fn test_protocols_display() {
        let rule = create_test_rule();
        assert_eq!(rule.protocols_display(), "SSH, RDP");
    }

    #[test]
    fn test_access_rule_detail_template_renders() {
        let template = AccessRuleDetailTemplate {
            title: "Rule Detail".to_string(),
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
        };
        let result = template.render();
        assert!(result.is_ok(), "AccessRuleDetailTemplate should render");
    }
}
