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
}
