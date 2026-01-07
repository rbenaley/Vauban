/// VAUBAN Web - Sidebar data structure.
use crate::templates::partials::sidebar_content::SidebarContentTemplate;

/// Sidebar data (not a template itself, used as data in includes).
#[derive(Debug, Clone)]
pub struct SidebarTemplate {
    pub sidebar_content: SidebarContentTemplate,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::templates::base::UserContext;

    fn create_test_user() -> UserContext {
        UserContext {
            uuid: "test-uuid".to_string(),
            username: "testuser".to_string(),
            display_name: "Test User".to_string(),
            is_superuser: false,
            is_staff: false,
        }
    }

    fn create_test_sidebar_content() -> SidebarContentTemplate {
        SidebarContentTemplate {
            user: create_test_user(),
            is_dashboard: true,
            is_assets: false,
            is_sessions: false,
            is_recordings: false,
            is_users: false,
            is_groups: false,
            is_approvals: false,
            is_access_rules: false,
            can_view_groups: false,
            can_view_access_rules: false,
        }
    }

    #[test]
    fn test_sidebar_template_creation() {
        let template = SidebarTemplate {
            sidebar_content: create_test_sidebar_content(),
        };
        assert!(template.sidebar_content.is_dashboard);
    }

    #[test]
    fn test_sidebar_template_with_admin() {
        let mut content = create_test_sidebar_content();
        content.user.is_superuser = true;
        content.user.is_staff = true;
        content.can_view_groups = true;
        content.can_view_access_rules = true;

        let template = SidebarTemplate {
            sidebar_content: content,
        };
        assert!(template.sidebar_content.user.is_superuser);
        assert!(template.sidebar_content.can_view_groups);
    }

    #[test]
    fn test_sidebar_template_clone() {
        let template = SidebarTemplate {
            sidebar_content: create_test_sidebar_content(),
        };
        let cloned = template.clone();
        assert_eq!(
            template.sidebar_content.user.uuid,
            cloned.sidebar_content.user.uuid
        );
    }
}
