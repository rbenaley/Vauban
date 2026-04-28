/// VAUBAN Web - Group add member template.
use askama::Template;

use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};

/// Basic group info for add member page.
#[derive(Debug, Clone)]
pub struct GroupInfo {
    pub uuid: String,
    pub name: String,
}

/// Available user to add to group.
#[derive(Debug, Clone)]
pub struct AvailableUser {
    pub uuid: String,
    pub username: String,
    pub email: String,
}

#[derive(Template)]
#[template(path = "accounts/group_add_member.html")]
pub struct GroupAddMemberTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub group: GroupInfo,
    pub available_users: Vec<AvailableUser>,
    /// Drives the empty-state copy in `_group_add_member_list.html`.
    /// Always `false` for the initial page render; the HTMX search
    /// response uses `GroupAddMemberListPartial` with `is_search = true`.
    pub is_search: bool,
}

/// HTMX partial for the live search results on
/// `/accounts/groups/{uuid}/members/search`. Renders the inner content
/// of `#user-list` (no surrounding wrapper, no `{% extends %}`) so the
/// default HTMX `innerHTML` swap drops the bytes straight in.
///
/// Shares its template file with the initial render of
/// `GroupAddMemberTemplate`, so the user-item HTML, CSRF wiring, and
/// form action stay identical between the two code paths.
#[derive(Template)]
#[template(path = "accounts/_group_add_member_list.html")]
pub struct GroupAddMemberListPartial {
    pub group: GroupInfo,
    pub available_users: Vec<AvailableUser>,
    pub is_search: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_available_user() -> AvailableUser {
        AvailableUser {
            uuid: "user-uuid-123".to_string(),
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
        }
    }

    #[test]
    fn test_available_user_creation() {
        let user = create_test_available_user();
        assert_eq!(user.username, "testuser");
    }

    #[test]
    fn test_group_add_member_template_renders() {
        use crate::templates::base::{UserContext, VaubanConfig};

        let template = GroupAddMemberTemplate {
            title: "Add Member".to_string(),
            user: Some(UserContext {
                uuid: "admin-uuid".to_string(),
                username: "admin".to_string(),
                display_name: "Admin User".to_string(),
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
            group: GroupInfo {
                uuid: "group-uuid".to_string(),
                name: "Test Group".to_string(),
            },
            available_users: vec![create_test_available_user()],
            is_search: false,
        };

        let result = template.render();
        assert!(result.is_ok(), "GroupAddMemberTemplate should render");
    }

    #[test]
    fn test_group_add_member_template_empty_users() {
        use crate::templates::base::{UserContext, VaubanConfig};

        let template = GroupAddMemberTemplate {
            title: "Add Member".to_string(),
            user: Some(UserContext {
                uuid: "admin-uuid".to_string(),
                username: "admin".to_string(),
                display_name: "Admin User".to_string(),
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
            group: GroupInfo {
                uuid: "group-uuid".to_string(),
                name: "Test Group".to_string(),
            },
            available_users: vec![],
            is_search: false,
        };

        let result = template.render();
        assert!(
            result.is_ok(),
            "Template should render with empty user list"
        );
    }

    /// `GroupAddMemberListPartial` with users renders the form items,
    /// uses Alpine's `x-data="csrf"` (never an empty CSRF input), and
    /// auto-escapes username/email so the response is XSS-safe.
    #[test]
    fn test_group_add_member_list_partial_renders_users_with_csrf() {
        let partial = GroupAddMemberListPartial {
            group: GroupInfo {
                uuid: "group-uuid".to_string(),
                name: "Test Group".to_string(),
            },
            available_users: vec![create_test_available_user()],
            is_search: true,
        };

        let html = partial.render().expect("partial must render");

        assert!(
            html.contains("testuser"),
            "user list must include the username"
        );
        assert!(
            html.contains(r#"x-data="csrf""#),
            "form must opt into the Alpine CSRF component"
        );
        assert!(
            html.contains(r#"x-model="token""#),
            "CSRF input must be bound to the Alpine token model"
        );
        // Forbidden anti-pattern: empty CSRF input expecting some
        // vanilla-JS hook to populate it (see front-end-design SKILL).
        assert!(
            !html.contains(r#"name="csrf_token" />"#) && !html.contains(r#"name="csrf_token">"#),
            "CSRF input must not be empty (Alpine x-model is required)"
        );
    }

    /// Empty list + `is_search = true` shows the search-specific copy.
    #[test]
    fn test_group_add_member_list_partial_search_empty_message() {
        let partial = GroupAddMemberListPartial {
            group: GroupInfo {
                uuid: "group-uuid".to_string(),
                name: "Test Group".to_string(),
            },
            available_users: vec![],
            is_search: true,
        };

        let html = partial.render().expect("partial must render");
        assert!(
            html.contains("No matching users found."),
            "search empty state must use the search-specific copy"
        );
    }

    /// Empty list + `is_search = false` shows the initial-render copy.
    #[test]
    fn test_group_add_member_list_partial_initial_empty_message() {
        let partial = GroupAddMemberListPartial {
            group: GroupInfo {
                uuid: "group-uuid".to_string(),
                name: "Test Group".to_string(),
            },
            available_users: vec![],
            is_search: false,
        };

        let html = partial.render().expect("partial must render");
        assert!(
            html.contains("All users are already members of this group."),
            "initial empty state must use the all-members copy"
        );
    }

    /// Askama auto-escape protects username/email from XSS even if a
    /// future relaxation of upstream validation lets `<` slip in.
    #[test]
    fn test_group_add_member_list_partial_escapes_username_and_email() {
        let partial = GroupAddMemberListPartial {
            group: GroupInfo {
                uuid: "group-uuid".to_string(),
                name: "Test Group".to_string(),
            },
            available_users: vec![AvailableUser {
                uuid: "evil-uuid".to_string(),
                username: "<script>alert(1)</script>".to_string(),
                email: "x@<svg/onload=alert(1)>".to_string(),
            }],
            is_search: true,
        };

        let html = partial.render().expect("partial must render");
        assert!(
            !html.contains("<script>alert(1)</script>"),
            "raw <script> must be escaped, got: {html}"
        );
        assert!(
            !html.contains("<svg/onload=alert(1)>"),
            "raw <svg/onload=...> must be escaped, got: {html}"
        );
        // Askama may emit either the named entity (&lt;) or the numeric
        // entity (&#60;); both are valid escapes. Accept either.
        let escaped_lt = html.contains("&lt;script") || html.contains("&#60;script");
        assert!(
            escaped_lt,
            "expected an entity-encoded script tag (named or numeric), got: {html}"
        );
    }
}
