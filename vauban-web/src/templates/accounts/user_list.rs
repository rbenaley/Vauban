use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};
use crate::templates::partials::sidebar_content::SidebarContentTemplate;
/// VAUBAN Web - User list template.
use askama::Template;

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
    /// Sanitized `?sort=` value (`last_login` / `-last_login`), `None`
    /// for the default `username ASC` ordering.
    pub sort: Option<String>,
}

impl UserListTemplate {
    /// `&key=value` suffix carrying every active filter + sort, for
    /// the `?page=N` pagination links (single source of truth:
    /// `services::list_filters::query_suffix`).
    pub fn filter_query_suffix(&self) -> String {
        crate::services::list_filters::query_suffix(&[
            ("search", &self.search),
            ("status", &self.status_filter),
            ("sort", &self.sort),
        ])
    }

    /// The `?sort=` value the "Last Login" header click should
    /// request next: none -> oldest-first (NULLS FIRST, the dormant
    /// accounts), oldest-first -> newest-first, newest-first -> back
    /// to the default username ordering.
    pub fn next_last_login_sort(&self) -> &'static str {
        match self.sort.as_deref() {
            Some("last_login") => "-last_login",
            Some("-last_login") => "",
            _ => "last_login",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn template_with_sort(sort: Option<&str>) -> UserListTemplate {
        UserListTemplate {
            title: "Users".to_string(),
            user: None,
            vauban: VaubanConfig::default(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
            users: Vec::new(),
            pagination: None,
            search: None,
            status_filter: None,
            sort: sort.map(str::to_string),
        }
    }

    // ---- next_last_login_sort: the 3-state cycle ----

    #[test]
    fn test_next_sort_cycles_none_to_ascending() {
        assert_eq!(
            template_with_sort(None).next_last_login_sort(),
            "last_login"
        );
    }

    #[test]
    fn test_next_sort_cycles_ascending_to_descending() {
        assert_eq!(
            template_with_sort(Some("last_login")).next_last_login_sort(),
            "-last_login"
        );
    }

    #[test]
    fn test_next_sort_cycles_descending_back_to_default() {
        assert_eq!(
            template_with_sort(Some("-last_login")).next_last_login_sort(),
            ""
        );
    }

    #[test]
    fn test_filter_query_suffix_carries_sort() {
        let mut tpl = template_with_sort(Some("last_login"));
        tpl.search = Some("ali ce".to_string());
        assert_eq!(
            tpl.filter_query_suffix(),
            "&search=ali%20ce&sort=last_login"
        );
    }

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

    #[test]
    fn test_user_list_template_renders() {
        use crate::templates::base::VaubanConfig;

        let template = UserListTemplate {
            title: "Users".to_string(),
            user: Some(UserContext {
                uuid: "test".to_string(),
                username: "testuser".to_string(),
                display_name: "Test User".to_string(),
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
            users: vec![UserListItem {
                uuid: "test-uuid".to_string(),
                username: "testuser".to_string(),
                email: "test@example.com".to_string(),
                full_name: Some("Test User".to_string()),
                auth_source: "local".to_string(),
                mfa_enabled: true,
                is_active: true,
                is_staff: false,
                is_superuser: false,
                last_login: None,
            }],
            search: None,
            status_filter: None,
            sort: None,
            pagination: Some(create_test_pagination(1, 1)),
        };

        let result = template.render();
        assert!(result.is_ok(), "UserListTemplate should render");
    }
}
