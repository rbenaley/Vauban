/// VAUBAN Web - Sidebar content data structure.
use crate::auth::PermissionContext;
use crate::templates::base::UserContext;

/// Sidebar content data (not a template itself, used as data in includes).
///
/// `perms` is the Casbin-backed [`PermissionContext`] pre-computed by
/// [`crate::middleware::permissions::permission_context_middleware`] and
/// injected by [`crate::handlers::web::apply_sidebar_rbac`]. It is the
/// **only** source of truth for UI gating: templates must read
/// `sc.perms.<resource>_<action>` and must not branch on
/// `sc.user.is_staff` or `sc.user.is_superuser`.
#[derive(Debug, Clone)]
pub struct SidebarContentTemplate {
    pub user: UserContext,
    pub is_dashboard: bool,
    pub is_assets: bool,
    /// Active state for the admin "Manage Assets" link
    /// (`/assets/manage/*`) — issue #27 asset zone split.
    pub is_manage_assets: bool,
    pub is_sessions: bool,
    pub is_recordings: bool,
    pub is_users: bool,
    pub is_groups: bool,
    pub is_approvals: bool,
    pub is_access_rules: bool,
    pub is_my_requests: bool,
    /// Number of pending approval requests (shown as badge for admins).
    pub pending_approval_count: i64,
    /// Casbin-backed permission context. Sole source of truth for UI gates.
    pub perms: PermissionContext,
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

    fn make_sidebar(user: UserContext, perms: PermissionContext) -> SidebarContentTemplate {
        SidebarContentTemplate {
            user,
            is_dashboard: false,
            is_assets: false,
            is_manage_assets: false,
            is_sessions: false,
            is_recordings: false,
            is_users: false,
            is_groups: false,
            is_approvals: false,
            is_access_rules: false,
            is_my_requests: false,
            pending_approval_count: 0,
            perms,
        }
    }

    fn admin_perms() -> PermissionContext {
        PermissionContext {
            users_read: true,
            users_write: true,
            groups_read: true,
            groups_write: true,
            access_rules_read: true,
            access_rules_write: true,
            assets_read: true,
            assets_manage: true,
            admin_view: true,
            auth_sessions_read: true,
            auth_sessions_write: true,
            sessions_read: true,
            sessions_write: true,
            profile_read: true,
            profile_write: true,
            users_manage_admins: true,
            assets_read_all: true,
            groups_manage_members: true,
            sessions_supervise: true,
            sessions_bypass_access_rules: true,
        }
    }

    #[test]
    fn test_sidebar_content_dashboard_active() {
        let mut sidebar = make_sidebar(create_test_user(), PermissionContext::default());
        sidebar.is_dashboard = true;
        assert!(sidebar.is_dashboard);
        assert!(!sidebar.is_assets);
    }

    #[test]
    fn test_sidebar_content_assets_active() {
        let mut sidebar = make_sidebar(create_test_user(), PermissionContext::default());
        sidebar.is_assets = true;
        assert!(!sidebar.is_dashboard);
        assert!(sidebar.is_assets);
    }

    #[test]
    fn test_sidebar_content_admin_permissions() {
        let sidebar = make_sidebar(create_admin_user(), admin_perms());
        assert!(sidebar.perms.groups_read);
        assert!(sidebar.perms.access_rules_read);
        assert!(sidebar.perms.admin_view);
        assert!(sidebar.user.is_superuser);
    }

    #[test]
    fn test_sidebar_content_regular_user_permissions() {
        let sidebar = make_sidebar(create_test_user(), PermissionContext::default());
        assert!(!sidebar.perms.groups_read);
        assert!(!sidebar.perms.access_rules_read);
        assert!(!sidebar.perms.admin_view);
    }

    #[test]
    fn test_sidebar_content_clone() {
        let sidebar = make_sidebar(create_test_user(), PermissionContext::default());
        let cloned = sidebar.clone();
        assert_eq!(sidebar.user.uuid, cloned.user.uuid);
        assert_eq!(sidebar.perms.admin_view, cloned.perms.admin_view);
    }

    #[test]
    fn test_sidebar_content_debug() {
        let sidebar = make_sidebar(create_test_user(), PermissionContext::default());
        let debug_str = format!("{:?}", sidebar);
        assert!(debug_str.contains("SidebarContentTemplate"));
        assert!(debug_str.contains("perms"));
    }

    #[test]
    fn test_sidebar_admin_visible_for_superuser() {
        let sidebar = make_sidebar(create_admin_user(), admin_perms());
        assert!(sidebar.perms.admin_view);
        assert!(sidebar.user.is_superuser);
    }

    #[test]
    fn test_sidebar_admin_visible_for_staff() {
        let sidebar = make_sidebar(create_staff_user(), admin_perms());
        assert!(sidebar.perms.admin_view);
        assert!(sidebar.user.is_staff);
        assert!(!sidebar.user.is_superuser);
    }

    #[test]
    fn test_sidebar_admin_hidden_for_normal_user() {
        let sidebar = make_sidebar(create_test_user(), PermissionContext::default());
        assert!(!sidebar.perms.admin_view);
        assert!(!sidebar.user.is_staff);
        assert!(!sidebar.user.is_superuser);
    }
}
