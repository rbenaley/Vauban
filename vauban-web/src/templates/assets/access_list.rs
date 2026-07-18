use crate::models::AssetType;
use crate::templates::accounts::user_list::Pagination;
use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};
/// VAUBAN Web - Access list template.
use askama::Template;

/// Access rule item for the list view.
#[derive(Debug, Clone)]
pub struct AccessRuleListItem {
    pub uuid: String,
    pub name: String,
    pub user_group_name: String,
    pub asset_group_name: String,
    pub allowed_protocols: Vec<String>,
    pub is_active: bool,
    pub require_mfa: bool,
    pub require_approval: bool,
}

impl AccessRuleListItem {
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
            .map(|p| AssetType::format_access_rule_protocol(p))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

#[derive(Template)]
#[template(path = "assets/access_list.html")]
pub struct AccessListTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub rules: Vec<AccessRuleListItem>,
    pub pagination: Option<Pagination>,
    pub search: Option<String>,
    pub protocol_filter: Option<String>,
    pub status_filter: Option<String>,
}

impl AccessListTemplate {
    /// True when at least one live filter narrows the list; drives the
    /// double-branch empty state ("no matching" vs "none configured").
    #[must_use]
    pub fn has_filters(&self) -> bool {
        self.search.is_some() || self.protocol_filter.is_some() || self.status_filter.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_vauban_config() -> VaubanConfig {
        VaubanConfig {
            brand_name: "VAUBAN".to_string(),
            brand_logo: None,
            theme: "dark".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn test_access_list_template_creation() {
        let template = AccessListTemplate {
            title: "Access List".to_string(),
            user: None,
            vauban: create_test_vauban_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
            rules: Vec::new(),
            pagination: None,
            search: None,
            protocol_filter: None,
            status_filter: None,
        };
        assert_eq!(template.title, "Access List");
    }

    #[test]
    fn test_access_list_template_renders() {
        let template = AccessListTemplate {
            title: "Access List".to_string(),
            user: None,
            vauban: create_test_vauban_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
            rules: Vec::new(),
            pagination: None,
            search: None,
            protocol_filter: None,
            status_filter: None,
        };
        let result = template.render();
        assert!(result.is_ok());
    }

    #[test]
    fn test_access_rule_list_item_status_class() {
        let active = AccessRuleListItem {
            uuid: "u".to_string(),
            name: "r".to_string(),
            user_group_name: "g".to_string(),
            asset_group_name: "a".to_string(),
            allowed_protocols: vec!["ssh".to_string()],
            is_active: true,
            require_mfa: false,
            require_approval: false,
        };
        assert!(active.status_class().contains("green"));

        let inactive = AccessRuleListItem {
            is_active: false,
            ..active.clone()
        };
        assert!(inactive.status_class().contains("red"));
    }

    #[test]
    fn test_protocols_display() {
        let item = AccessRuleListItem {
            uuid: "u".to_string(),
            name: "r".to_string(),
            user_group_name: "g".to_string(),
            asset_group_name: "a".to_string(),
            allowed_protocols: vec!["ssh".to_string(), "rdp".to_string()],
            is_active: true,
            require_mfa: false,
            require_approval: false,
        };
        assert_eq!(item.protocols_display(), "SSH, RDP");
    }

    #[test]
    fn test_protocols_display_iacs_family() {
        let item = AccessRuleListItem {
            uuid: "u".to_string(),
            name: "r".to_string(),
            user_group_name: "g".to_string(),
            asset_group_name: "a".to_string(),
            allowed_protocols: vec![
                "ssh".to_string(),
                "rdp".to_string(),
                "iacs_modbus".to_string(),
                "iacs_opcua".to_string(),
                "iacs_profinet".to_string(),
                "iacs_iec104".to_string(),
                "iacs_tcp".to_string(),
            ],
            is_active: true,
            require_mfa: false,
            require_approval: false,
        };
        assert_eq!(
            item.protocols_display(),
            "SSH, RDP, Modbus, OPC UA, PROFINET, IEC-104, IACS (TCP)"
        );
    }
}
