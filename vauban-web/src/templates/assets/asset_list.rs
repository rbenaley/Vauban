use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};
/// VAUBAN Web - Asset list template.
use askama::Template;

use crate::templates::accounts::user_list::Pagination;

/// Asset item for list display.
///
/// Issue #34: `require_mfa` is now carried per-row so the
/// `Request Access` modal -- which is INLINED on `/assets` -- can
/// know whether to render the TOTP field without a detour through a
/// detail page. `require_mfa` is computed from the access_rules of
/// the current user against this asset's groups (and the virtual
/// all-assets group); same predicate as the legacy `asset_user_view`
/// used. `requires_request` already follows the same per-user rule.
#[derive(Debug, Clone)]
pub struct AssetListItem {
    pub id: i32,
    pub uuid: ::uuid::Uuid,
    pub name: String,
    pub hostname: String,
    pub port: i32,
    pub asset_type: String, // "ssh", "rdp"
    pub status: String,     // "online", "offline", "maintenance"
    pub group_name: Option<String>,
    pub requires_request: bool,
    /// Per-user, per-asset: true when the access rule covering this
    /// asset for the current caller has `require_mfa = true`. Drives
    /// the TOTP field of the inlined Request Access modal.
    pub require_mfa: bool,
}

#[derive(Template)]
#[template(path = "assets/asset_list.html")]
pub struct AssetListTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub assets: Vec<AssetListItem>,
    pub pagination: Option<Pagination>,
    pub search: Option<String>,
    pub type_filter: Option<String>,
    pub status_filter: Option<String>,
    pub asset_types: Vec<(String, String)>,
    pub statuses: Vec<(String, String)>,
    /// Whether to require justification before connecting (SEC-03).
    pub require_justification: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_asset_item() -> AssetListItem {
        AssetListItem {
            id: 1,
            uuid: ::uuid::Uuid::new_v4(),
            name: "Test Server".to_string(),
            hostname: "test.example.com".to_string(),
            port: 22,
            asset_type: "ssh".to_string(),
            status: "online".to_string(),
            group_name: Some("Production".to_string()),
            requires_request: false,
            require_mfa: false,
        }
    }

    #[test]
    fn test_asset_list_item_creation() {
        let item = create_test_asset_item();
        assert_eq!(item.name, "Test Server");
        assert_eq!(item.port, 22);
    }

    #[test]
    fn test_asset_list_item_without_group() {
        let mut item = create_test_asset_item();
        item.group_name = None;
        assert!(item.group_name.is_none());
    }

    #[test]
    fn test_asset_list_item_clone() {
        let item = create_test_asset_item();
        let cloned = item.clone();
        assert_eq!(item.id, cloned.id);
        assert_eq!(item.hostname, cloned.hostname);
    }

    #[test]
    fn test_asset_list_item_types() {
        let ssh = AssetListItem {
            asset_type: "ssh".to_string(),
            ..create_test_asset_item()
        };
        let rdp = AssetListItem {
            asset_type: "rdp".to_string(),
            ..create_test_asset_item()
        };

        assert_eq!(ssh.asset_type, "ssh");
        assert_eq!(rdp.asset_type, "rdp");
    }

    #[test]
    fn test_asset_list_item_statuses() {
        let online = AssetListItem {
            status: "online".to_string(),
            ..create_test_asset_item()
        };
        let offline = AssetListItem {
            status: "offline".to_string(),
            ..create_test_asset_item()
        };
        let maint = AssetListItem {
            status: "maintenance".to_string(),
            ..create_test_asset_item()
        };

        assert_eq!(online.status, "online");
        assert_eq!(offline.status, "offline");
        assert_eq!(maint.status, "maintenance");
    }

    #[test]
    fn test_asset_list_template_renders() {
        use crate::templates::base::{UserContext, VaubanConfig};

        let template = AssetListTemplate {
            title: "Assets".to_string(),
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
            assets: vec![create_test_asset_item()],
            pagination: None,
            search: None,
            type_filter: None,
            status_filter: None,
            asset_types: vec![],
            statuses: vec![],
            require_justification: true,
        };

        let result = template.render();
        assert!(result.is_ok(), "AssetListTemplate should render");
    }

    /// Issue #27 (asset zone split): the user-zone list NEVER shows a
    /// View link. The `show_view_link` field was removed from the
    /// template; the only actions on this page are `Connect` and
    /// `Request access`. CRUD lives at `/assets/manage/*`.
    #[test]
    fn test_asset_list_template_user_zone_has_no_view_field() {
        let source = include_str!("asset_list.rs");
        // Strip the test block so we only scan the production type.
        let body = source
            .split("#[cfg(test)]")
            .next()
            .expect("asset_list.rs always has a non-test prefix");
        let view_field = format!("show{}view{}link", "_", "_");
        assert!(
            !body.contains(view_field.as_str()),
            "AssetListTemplate must not carry a `{view_field}` field after issue #27 \
             (the user-zone list has no detail page; CRUD is admin-only at \
             /assets/manage/*)",
        );
    }

    fn make_template(
        pagination: Option<Pagination>,
        search: Option<String>,
        type_filter: Option<String>,
        status_filter: Option<String>,
    ) -> AssetListTemplate {
        AssetListTemplate {
            title: "Assets".to_string(),
            user: Some(UserContext {
                uuid: "u1".to_string(),
                username: "admin".to_string(),
                display_name: "Admin".to_string(),
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
            assets: vec![create_test_asset_item()],
            pagination,
            search,
            type_filter,
            status_filter,
            asset_types: vec![],
            statuses: vec![],
            require_justification: true,
        }
    }

    fn make_pagination(current: i32, total: i32, total_items: i32) -> Pagination {
        Pagination {
            current_page: current,
            total_pages: total,
            total_items,
            items_per_page: 30,
            has_previous: current > 1,
            has_next: current < total,
            start_index: (current - 1) * 30 + 1,
            end_index: (current * 30).min(total_items),
        }
    }

    #[test]
    fn test_pagination_first_page_has_next_no_previous() {
        let pg = make_pagination(1, 3, 90);
        let template = make_template(Some(pg), None, None, None);
        let html = template.render().expect("should render");
        assert!(html.contains("Showing"), "should show Showing X to Y");
        assert!(
            html.contains("of <span class=\"font-medium\">90</span>"),
            "should show total"
        );
        assert!(html.contains("?page=2"), "should have next page link");
        assert!(!html.contains("?page=0"), "should not have page 0");
        assert!(
            html.contains("title=\"Next page\""),
            "should have Next button"
        );
        assert!(
            html.contains("title=\"Last page\""),
            "should have Last button"
        );
        assert!(
            !html.contains("title=\"First page\""),
            "should not have First on page 1"
        );
        assert!(
            !html.contains("title=\"Previous page\""),
            "should not have Previous on page 1"
        );
    }

    #[test]
    fn test_pagination_last_page_has_previous_no_next() {
        let pg = make_pagination(3, 3, 90);
        let template = make_template(Some(pg), None, None, None);
        let html = template.render().expect("should render");
        assert!(
            html.contains("title=\"First page\""),
            "should have First button"
        );
        assert!(
            html.contains("title=\"Previous page\""),
            "should have Previous button"
        );
        assert!(
            !html.contains("title=\"Next page\""),
            "should not have Next on last page"
        );
        assert!(
            !html.contains("title=\"Last page\""),
            "should not have Last on last page"
        );
        assert!(
            html.contains("?page=1"),
            "should have link to page 1 (First)"
        );
        assert!(
            html.contains("?page=2"),
            "should have link to page 2 (Previous)"
        );
    }

    #[test]
    fn test_pagination_middle_page_has_all_nav() {
        let pg = make_pagination(2, 5, 150);
        let template = make_template(Some(pg), None, None, None);
        let html = template.render().expect("should render");
        assert!(html.contains("title=\"First page\""), "should have First");
        assert!(
            html.contains("title=\"Previous page\""),
            "should have Previous"
        );
        assert!(html.contains("title=\"Next page\""), "should have Next");
        assert!(html.contains("title=\"Last page\""), "should have Last");
        assert!(html.contains("?page=5"), "should link to last page (5)");
    }

    #[test]
    fn test_pagination_single_page_no_controls() {
        let template = make_template(None, None, None, None);
        let html = template.render().expect("should render");
        assert!(
            !html.contains("Showing"),
            "single page should not show pagination"
        );
        assert!(
            !html.contains("title=\"Next page\""),
            "no Next on single page"
        );
    }

    #[test]
    fn test_pagination_first_page_links_to_last() {
        let pg = make_pagination(1, 10, 300);
        let template = make_template(Some(pg), None, None, None);
        let html = template.render().expect("should render");
        assert!(html.contains("?page=10"), "should link to page 10 as last");
    }

    #[test]
    fn test_pagination_preserves_search_filter() {
        let pg = make_pagination(1, 3, 90);
        let template = make_template(Some(pg), Some("myserver".to_string()), None, None);
        let html = template.render().expect("should render");
        assert!(
            html.contains("search=myserver"),
            "next page link should preserve search filter"
        );
    }

    #[test]
    fn test_pagination_preserves_type_filter() {
        let pg = make_pagination(1, 3, 90);
        let template = make_template(Some(pg), None, Some("ssh".to_string()), None);
        let html = template.render().expect("should render");
        assert!(
            html.contains("type=ssh"),
            "page links should preserve type filter"
        );
    }

    #[test]
    fn test_pagination_preserves_status_filter() {
        let pg = make_pagination(2, 3, 90);
        let template = make_template(Some(pg), None, None, Some("online".to_string()));
        let html = template.render().expect("should render");
        assert!(
            html.contains("status=online"),
            "page links should preserve status filter"
        );
    }

    #[test]
    fn test_pagination_preserves_all_filters() {
        let pg = make_pagination(2, 5, 150);
        let template = make_template(
            Some(pg),
            Some("prod".to_string()),
            Some("rdp".to_string()),
            Some("offline".to_string()),
        );
        let html = template.render().expect("should render");
        assert!(html.contains("search=prod"), "should preserve search");
        assert!(html.contains("type=rdp"), "should preserve type");
        assert!(html.contains("status=offline"), "should preserve status");
    }

    #[test]
    fn test_pagination_showing_counter_values() {
        let pg = make_pagination(2, 3, 75);
        let template = make_template(Some(pg), None, None, None);
        let html = template.render().expect("should render");
        assert!(html.contains(">31</span>"), "start_index should be 31");
        assert!(html.contains(">60</span>"), "end_index should be 60");
        assert!(html.contains(">75</span>"), "total_items should be 75");
    }

    #[test]
    fn test_pagination_mobile_has_prev_next() {
        let pg = make_pagination(2, 3, 90);
        let template = make_template(Some(pg), None, None, None);
        let html = template.render().expect("should render");
        assert!(html.contains("sm:hidden"), "should have mobile container");
        assert!(
            html.contains(">Previous</a>") || html.contains(">\n                    Previous\n"),
            "mobile should have Previous button text"
        );
    }

    #[test]
    fn test_pagination_current_page_highlighted() {
        let pg = make_pagination(2, 5, 150);
        let template = make_template(Some(pg), None, None, None);
        let html = template.render().expect("should render");
        assert!(
            html.contains("aria-current=\"page\""),
            "current page should have aria-current"
        );
        assert!(
            html.contains("bg-vauban-600"),
            "current page should be highlighted"
        );
    }

    #[test]
    fn test_asset_requires_request_shows_request_label() {
        let mut item = create_test_asset_item();
        item.requires_request = true;
        let template = AssetListTemplate {
            title: "Assets".to_string(),
            user: Some(UserContext {
                uuid: "u1".to_string(),
                username: "user".to_string(),
                display_name: "User".to_string(),
                is_superuser: false,
                is_staff: false,
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
            assets: vec![item],
            pagination: None,
            search: None,
            type_filter: None,
            status_filter: None,
            asset_types: vec![],
            statuses: vec![],
            require_justification: true,
        };
        let html = template.render().expect("should render");
        assert!(html.contains("Request"), "should show Request label");
        // Issue #34: the per-row "Request" button now opens the inlined
        // Alpine-driven modal via `$store.accessModal.open(...)` with
        // the asset's uuid / type / require_mfa as arguments. The
        // legacy `<a href=".../#request-access">` navigation pattern
        // (which forced a detour through the now-removed
        // `/assets/{uuid}` detail page) is no longer rendered.
        assert!(
            html.contains("$store.accessModal.open("),
            "Request button must trigger the inlined Alpine accessModal"
        );
        assert!(
            !html.contains("#request-access"),
            "Request button must NOT use the legacy hash navigation \
             (the /assets/{{uuid}} detail page is gone, issue #34)"
        );
    }

    #[test]
    fn test_asset_no_request_shows_connect_direct() {
        let item = create_test_asset_item();
        let template = AssetListTemplate {
            title: "Assets".to_string(),
            user: Some(UserContext {
                uuid: "u1".to_string(),
                username: "user".to_string(),
                display_name: "User".to_string(),
                is_superuser: false,
                is_staff: false,
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
            assets: vec![item],
            pagination: None,
            search: None,
            type_filter: None,
            status_filter: None,
            asset_types: vec![],
            statuses: vec![],
            require_justification: false,
        };
        let html = template.render().expect("should render");
        assert!(html.contains("Connect"), "should show Connect label");
        assert!(
            html.contains("hx-post"),
            "Connect asset should have hx-post button when justification is disabled"
        );
    }

    #[test]
    fn test_asset_no_request_shows_connect_with_justification() {
        let item = create_test_asset_item();
        let template = AssetListTemplate {
            title: "Assets".to_string(),
            user: Some(UserContext {
                uuid: "u1".to_string(),
                username: "user".to_string(),
                display_name: "User".to_string(),
                is_superuser: false,
                is_staff: false,
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
            assets: vec![item],
            pagination: None,
            search: None,
            type_filter: None,
            status_filter: None,
            asset_types: vec![],
            statuses: vec![],
            require_justification: true,
        };
        let html = template.render().expect("should render");
        assert!(html.contains("Connect"), "should show Connect label");
        // Issue #34: the per-row "Connect" button on a row that
        // requires justification now opens the inlined Alpine
        // justificationModal via
        // `$store.justificationModal.open(uuid, type)` and the
        // form submit posts via `htmx.ajax(...)` to the URL
        // computed by `connectUrl()`.  No more hash detour through
        // the removed detail page.
        assert!(
            html.contains("$store.justificationModal.open("),
            "Connect button (require_justification on) must trigger \
             the inlined Alpine justificationModal"
        );
        assert!(
            !html.contains("#justify"),
            "Connect button must NOT use the legacy `#justify` hash \
             navigation (the /assets/{{uuid}} detail page is gone, \
             issue #34)"
        );
    }

    #[test]
    fn test_mixed_assets_render_both_labels() {
        let mut request_item = create_test_asset_item();
        request_item.requires_request = true;
        request_item.id = 2;
        let connect_item = create_test_asset_item();

        let template = AssetListTemplate {
            title: "Assets".to_string(),
            user: Some(UserContext {
                uuid: "u1".to_string(),
                username: "user".to_string(),
                display_name: "User".to_string(),
                is_superuser: false,
                is_staff: false,
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
            assets: vec![request_item, connect_item],
            pagination: None,
            search: None,
            type_filter: None,
            status_filter: None,
            asset_types: vec![],
            statuses: vec![],
            require_justification: false,
        };
        let html = template.render().expect("should render");
        assert!(html.contains("Request"), "should contain Request label");
        assert!(html.contains("Connect"), "should contain Connect label");
        // Issue #34 -- per-row "Request" button drives the inlined
        // Alpine modal; legacy hash link is gone.
        assert!(
            html.contains("$store.accessModal.open("),
            "should have inlined accessModal trigger for the Request button"
        );
        assert!(
            !html.contains("#request-access"),
            "must not use legacy `#request-access` hash navigation"
        );
        assert!(html.contains("hx-post"), "should have hx-post button");
    }

    #[test]
    fn test_ws_trigger_present_in_template() {
        let template = make_template(None, None, None, None);
        let html = template.render().expect("should render");
        assert!(
            html.contains("asset-ws-trigger"),
            "template should contain #asset-ws-trigger element"
        );
        assert!(
            html.contains("request_approved"),
            "WS trigger should listen for request_approved"
        );
        assert!(
            html.contains("htmx:wsAfterMessage"),
            "WS trigger should use htmx:wsAfterMessage"
        );
    }

    #[test]
    fn test_ws_trigger_preserves_filters() {
        let pg = make_pagination(2, 5, 150);
        let template = make_template(
            Some(pg),
            Some("myfilter".to_string()),
            Some("ssh".to_string()),
            Some("online".to_string()),
        );
        let html = template.render().expect("should render");
        let trigger_start = html
            .find("asset-ws-trigger")
            .expect("should contain trigger");
        let trigger_section = &html[trigger_start..trigger_start + 500];
        assert!(
            trigger_section.contains("search=myfilter"),
            "WS trigger hx-get should preserve search filter"
        );
        assert!(
            trigger_section.contains("type=ssh"),
            "WS trigger hx-get should preserve type filter"
        );
        assert!(
            trigger_section.contains("status=online"),
            "WS trigger hx-get should preserve status filter"
        );
        assert!(
            trigger_section.contains("page=2"),
            "WS trigger hx-get should preserve current page"
        );
    }
}
