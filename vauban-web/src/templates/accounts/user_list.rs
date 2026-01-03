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

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_pagination(current: i32, total: i32) -> Pagination {
        Pagination {
            current_page: current,
            total_pages: total,
            total_items: total * 10,
            items_per_page: 10,
            has_previous: current > 1,
            has_next: current < total,
            start_index: (current - 1) * 10 + 1,
            end_index: current * 10,
        }
    }

    // Tests for page_range()
    #[test]
    fn test_page_range_first_page() {
        let pagination = create_test_pagination(1, 10);
        let range = pagination.page_range();
        assert_eq!(range, vec![1, 2, 3]);
    }

    #[test]
    fn test_page_range_last_page() {
        let pagination = create_test_pagination(10, 10);
        let range = pagination.page_range();
        assert_eq!(range, vec![8, 9, 10]);
    }

    #[test]
    fn test_page_range_middle_page() {
        let pagination = create_test_pagination(5, 10);
        let range = pagination.page_range();
        assert_eq!(range, vec![3, 4, 5, 6, 7]);
    }

    #[test]
    fn test_page_range_single_page() {
        let pagination = create_test_pagination(1, 1);
        let range = pagination.page_range();
        assert_eq!(range, vec![1]);
    }

    #[test]
    fn test_page_range_two_pages_first() {
        let pagination = create_test_pagination(1, 2);
        let range = pagination.page_range();
        assert_eq!(range, vec![1, 2]);
    }

    #[test]
    fn test_page_range_two_pages_second() {
        let pagination = create_test_pagination(2, 2);
        let range = pagination.page_range();
        assert_eq!(range, vec![1, 2]);
    }

    #[test]
    fn test_page_range_three_pages_middle() {
        let pagination = create_test_pagination(2, 3);
        let range = pagination.page_range();
        assert_eq!(range, vec![1, 2, 3]);
    }

    #[test]
    fn test_page_range_near_start() {
        let pagination = create_test_pagination(2, 10);
        let range = pagination.page_range();
        assert_eq!(range, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_page_range_near_end() {
        let pagination = create_test_pagination(9, 10);
        let range = pagination.page_range();
        assert_eq!(range, vec![7, 8, 9, 10]);
    }

    // Tests for Pagination struct
    #[test]
    fn test_pagination_creation() {
        let pagination = create_test_pagination(3, 10);
        assert_eq!(pagination.current_page, 3);
        assert_eq!(pagination.total_pages, 10);
        assert_eq!(pagination.items_per_page, 10);
        assert!(pagination.has_previous);
        assert!(pagination.has_next);
    }

    #[test]
    fn test_pagination_first_page_no_previous() {
        let pagination = create_test_pagination(1, 5);
        assert!(!pagination.has_previous);
        assert!(pagination.has_next);
    }

    #[test]
    fn test_pagination_last_page_no_next() {
        let pagination = create_test_pagination(5, 5);
        assert!(pagination.has_previous);
        assert!(!pagination.has_next);
    }

    #[test]
    fn test_pagination_clone() {
        let pagination = create_test_pagination(3, 10);
        let cloned = pagination.clone();
        assert_eq!(pagination.current_page, cloned.current_page);
        assert_eq!(pagination.page_range(), cloned.page_range());
    }

    // Tests for UserListItem struct
    #[test]
    fn test_user_list_item_creation() {
        let user = UserListItem {
            uuid: "uuid-123".to_string(),
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            full_name: Some("Test User".to_string()),
            auth_source: "local".to_string(),
            mfa_enabled: true,
            is_active: true,
            is_staff: false,
            is_superuser: false,
            last_login: Some("2026-01-03 10:00:00".to_string()),
        };
        assert_eq!(user.username, "testuser");
        assert!(user.mfa_enabled);
        assert!(user.is_active);
    }

    #[test]
    fn test_user_list_item_without_full_name() {
        let user = UserListItem {
            uuid: "uuid-456".to_string(),
            username: "anotheruser".to_string(),
            email: "another@example.com".to_string(),
            full_name: None,
            auth_source: "ldap".to_string(),
            mfa_enabled: false,
            is_active: true,
            is_staff: true,
            is_superuser: false,
            last_login: None,
        };
        assert!(user.full_name.is_none());
        assert!(user.last_login.is_none());
        assert!(user.is_staff);
    }

    #[test]
    fn test_user_list_item_superuser() {
        let user = UserListItem {
            uuid: "uuid-789".to_string(),
            username: "admin".to_string(),
            email: "admin@example.com".to_string(),
            full_name: Some("Admin User".to_string()),
            auth_source: "local".to_string(),
            mfa_enabled: true,
            is_active: true,
            is_staff: true,
            is_superuser: true,
            last_login: Some("2026-01-03 09:00:00".to_string()),
        };
        assert!(user.is_superuser);
        assert!(user.is_staff);
    }

    #[test]
    fn test_user_list_item_clone() {
        let user = UserListItem {
            uuid: "uuid-clone".to_string(),
            username: "cloneuser".to_string(),
            email: "clone@example.com".to_string(),
            full_name: None,
            auth_source: "local".to_string(),
            mfa_enabled: false,
            is_active: false,
            is_staff: false,
            is_superuser: false,
            last_login: None,
        };
        let cloned = user.clone();
        assert_eq!(user.uuid, cloned.uuid);
        assert_eq!(user.username, cloned.username);
    }
}
