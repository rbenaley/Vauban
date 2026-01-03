/// VAUBAN Web - User list template.

use askama::Template;
use crate::templates::base::{UserContext, VaubanConfig, FlashMessage};
use crate::templates::partials::sidebar_content::SidebarContentTemplate;

/// User item for list display.
#[derive(Debug, Clone)]
pub struct UserListItem {
    pub uuid: String,
    pub username: String,
    pub email: String,
    pub full_name: Option<String>,
    pub auth_source: String,
    pub mfa_enabled: bool,
    pub is_active: bool,
    pub is_staff: bool,
    pub is_superuser: bool,
    pub last_login: Option<String>,
}

/// Pagination information.
#[derive(Debug, Clone)]
pub struct Pagination {
    pub current_page: i32,
    pub total_pages: i32,
    pub total_items: i32,
    pub items_per_page: i32,
    pub has_previous: bool,
    pub has_next: bool,
    pub start_index: i32,
    pub end_index: i32,
}

impl Pagination {
    pub fn page_range(&self) -> Vec<i32> {
        let mut range = Vec::new();
        let start = (self.current_page - 2).max(1);
        let end = (self.current_page + 2).min(self.total_pages);
        for i in start..=end {
            range.push(i);
        }
        range
    }
}

#[derive(Template)]
#[template(path = "accounts/user_list.html")]
pub struct UserListTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content: Option<SidebarContentTemplate>,
    pub header_user: Option<UserContext>,
    pub users: Vec<UserListItem>,
    pub pagination: Option<Pagination>,
    pub search: Option<String>,
    pub status_filter: Option<String>,
}
