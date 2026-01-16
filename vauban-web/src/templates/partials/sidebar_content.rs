/// VAUBAN Web - Sidebar content data structure.
use crate::templates::base::UserContext;

/// Sidebar content data (not a template itself, used as data in includes).
#[derive(Debug, Clone)]
pub struct SidebarContentTemplate {
    pub user: UserContext,
    pub is_dashboard: bool,
    pub is_assets: bool,
    pub is_sessions: bool,
    pub is_recordings: bool,
    pub is_users: bool,
    pub is_groups: bool,
    pub is_approvals: bool,
    pub is_access_rules: bool,
    pub can_view_groups: bool,
    pub can_view_access_rules: bool,
    /// Whether the user can view the Administration section (superuser or staff).
    pub can_view_admin: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_user() -> UserContext {
        UserContext {
            uuid: "test-uuid".to_string(),
            username: "testuser".to_string(),
            display_name: "Test User".to_string(),
            is_superuser: false,
            is_staff: false,
        }
    }

    fn create_admin_user() -> UserContext {
        UserContext {
            uuid: "admin-uuid".to_string(),
            username: "admin".to_string(),
            display_name: "Administrator".to_string(),
            is_superuser: true,
            is_staff: true,
        }
    }

    fn create_staff_user() -> UserContext {
        UserContext {
            uuid: "staff-uuid".to_string(),
            username: "staff".to_string(),
            display_name: "Staff User".to_string(),
            is_superuser: false,
            is_staff: true,
        }
    }

    #[test]
    fn test_sidebar_content_dashboard_active() {
        let sidebar = SidebarContentTemplate {
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
            can_view_admin: false,
        };

        assert!(sidebar.is_dashboard);
        assert!(!sidebar.is_assets);
    }

    #[test]
    fn test_sidebar_content_assets_active() {
        let sidebar = SidebarContentTemplate {
            user: create_test_user(),
            is_dashboard: false,
            is_assets: true,
            is_sessions: false,
            is_recordings: false,
            is_users: false,
            is_groups: false,
            is_approvals: false,
            is_access_rules: false,
            can_view_groups: false,
            can_view_access_rules: false,
            can_view_admin: false,
        };

        assert!(!sidebar.is_dashboard);
        assert!(sidebar.is_assets);
    }

    #[test]
    fn test_sidebar_content_admin_permissions() {
        let sidebar = SidebarContentTemplate {
            user: create_admin_user(),
            is_dashboard: false,
            is_assets: false,
            is_sessions: false,
            is_recordings: false,
            is_users: false,
            is_groups: true,
            is_approvals: false,
            is_access_rules: false,
            can_view_groups: true,
            can_view_access_rules: true,
            can_view_admin: true,
        };

        assert!(sidebar.can_view_groups);
        assert!(sidebar.can_view_access_rules);
        assert!(sidebar.can_view_admin);
        assert!(sidebar.user.is_superuser);
    }

    #[test]
    fn test_sidebar_content_regular_user_permissions() {
        let sidebar = SidebarContentTemplate {
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
            can_view_admin: false,
        };

        assert!(!sidebar.can_view_groups);
        assert!(!sidebar.can_view_access_rules);
        assert!(!sidebar.can_view_admin);
    }

    #[test]
    fn test_sidebar_content_clone() {
        let sidebar = SidebarContentTemplate {
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
            can_view_admin: false,
        };
        let cloned = sidebar.clone();

        assert_eq!(sidebar.user.uuid, cloned.user.uuid);
        assert_eq!(sidebar.is_dashboard, cloned.is_dashboard);
        assert_eq!(sidebar.can_view_admin, cloned.can_view_admin);
    }

    #[test]
    fn test_sidebar_content_debug() {
        let sidebar = SidebarContentTemplate {
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
            can_view_admin: false,
        };
        let debug_str = format!("{:?}", sidebar);

        assert!(debug_str.contains("SidebarContentTemplate"));
        assert!(debug_str.contains("is_dashboard"));
        assert!(debug_str.contains("can_view_admin"));
    }

    #[test]
    fn test_sidebar_admin_visible_for_superuser() {
        let sidebar = SidebarContentTemplate {
            user: create_admin_user(),
            is_dashboard: true,
            is_assets: false,
            is_sessions: false,
            is_recordings: false,
            is_users: false,
            is_groups: false,
            is_approvals: false,
            is_access_rules: false,
            can_view_groups: true,
            can_view_access_rules: true,
            can_view_admin: true,
        };

        assert!(sidebar.can_view_admin);
        assert!(sidebar.user.is_superuser);
    }

    #[test]
    fn test_sidebar_admin_visible_for_staff() {
        let sidebar = SidebarContentTemplate {
            user: create_staff_user(),
            is_dashboard: true,
            is_assets: false,
            is_sessions: false,
            is_recordings: false,
            is_users: false,
            is_groups: false,
            is_approvals: false,
            is_access_rules: false,
            can_view_groups: true,
            can_view_access_rules: true,
            can_view_admin: true,
        };

        assert!(sidebar.can_view_admin);
        assert!(sidebar.user.is_staff);
        assert!(!sidebar.user.is_superuser);
    }

    #[test]
    fn test_sidebar_admin_hidden_for_normal_user() {
        let sidebar = SidebarContentTemplate {
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
            can_view_admin: false,
        };

        assert!(!sidebar.can_view_admin);
        assert!(!sidebar.user.is_staff);
        assert!(!sidebar.user.is_superuser);
    }
}
