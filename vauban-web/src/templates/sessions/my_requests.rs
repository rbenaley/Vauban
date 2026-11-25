use crate::templates::accounts::user_list::Pagination;
use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};
/// VAUBAN Web - My access requests template.
use askama::Template;

/// User access request item.
#[derive(Debug, Clone)]
pub struct MyRequestItem {
    pub uuid: String,
    /// The asset's UUID (not the request's): the Connect control of an
    /// approved request posts to `/assets/{asset_uuid}/connect*`, the
    /// endpoints the asset list uses.
    pub asset_uuid: String,
    pub asset_name: String,
    pub asset_hostname: String,
    pub asset_type: String,
    /// Pre-resolved `AssetType::is_iacs()`, as on the asset list.
    pub is_iacs: bool,
    /// An access rule of the caller requires a second factor for this
    /// asset. Display hint, as on the asset list; the server decides.
    pub require_mfa: bool,
    pub session_type: String,
    pub status: String,
    pub justification: Option<String>,
    pub created_at: String,
    pub approved_at: Option<String>,
    pub approved_by: Option<String>,
    pub max_session_duration: Option<i32>,
    /// MCP access decision stamped on a terminated visit. Present only
    /// when the subject may open a contestation.
    pub decision_id: Option<String>,
    /// The contestation of `decision_id`, if any: a decision is contested
    /// once, so its presence replaces the Contest form.
    pub contestation: Option<MyContestation>,
}

#[derive(Debug, Clone)]
pub struct MyContestation {
    pub uuid: String,
    pub status_label: &'static str,
}

impl MyRequestItem {
    pub fn status_class(&self) -> &str {
        super::session_status_class(&self.status)
    }

    /// User-friendly label for display (avoids raw DB statuses).
    /// Kept in lock-step with `status_vocab::MY_REQUESTS`.
    pub fn status_label(&self) -> &str {
        match self.status.as_str() {
            "pending" => "Pending",
            "approved" => "Approved",
            "rejected" => "Rejected",
            "revoked" => "Revoked",
            "expired" => "Expired",
            "active" => "Connected",
            "disconnected" => "Completed",
            "terminated" => "Terminated",
            _ => "Unknown",
        }
    }

    pub fn is_pending(&self) -> bool {
        self.status == "pending"
    }

    pub fn is_approved(&self) -> bool {
        self.status == "approved"
    }

    /// Human-readable duration display (e.g. "2h", "30min", "Unlimited").
    pub fn duration_display(&self) -> String {
        crate::utils::duration_display(self.max_session_duration)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_item(status: &str, duration: Option<i32>) -> MyRequestItem {
        MyRequestItem {
            uuid: "uuid-123".to_string(),
            asset_uuid: "asset-uuid-1".to_string(),
            is_iacs: false,
            require_mfa: false,
            asset_name: "Server A".to_string(),
            asset_hostname: "srv-a.local".to_string(),
            asset_type: "linux".to_string(),
            session_type: "ssh".to_string(),
            status: status.to_string(),
            justification: Some("Maintenance".to_string()),
            created_at: "Mar 30, 2026 10:00".to_string(),
            approved_at: None,
            approved_by: None,
            max_session_duration: duration,
            decision_id: None,
            contestation: None,
        }
    }

    // ---- status_class ----

    #[test]
    fn test_status_class_pending() {
        assert!(make_item("pending", None).status_class().contains("yellow"));
    }

    #[test]
    fn test_status_class_approved() {
        assert!(make_item("approved", None).status_class().contains("green"));
    }

    #[test]
    fn test_status_class_rejected() {
        assert!(make_item("rejected", None).status_class().contains("red"));
    }

    #[test]
    fn test_status_class_revoked() {
        assert!(make_item("revoked", None).status_class().contains("red"));
    }

    #[test]
    fn test_status_class_expired() {
        assert!(make_item("expired", None).status_class().contains("gray"));
    }

    #[test]
    fn test_status_class_phantom_consumed_falls_back_to_gray() {
        // 'consumed' was purged from the vocabulary (July 2026 status
        // audit): it is no longer classified.
        assert!(make_item("consumed", None).status_class().contains("gray"));
    }

    #[test]
    fn test_status_class_active() {
        assert!(make_item("active", None).status_class().contains("blue"));
    }

    #[test]
    fn test_status_class_disconnected() {
        assert!(
            make_item("disconnected", None)
                .status_class()
                .contains("indigo")
        );
    }

    #[test]
    fn test_status_class_terminated() {
        assert!(
            make_item("terminated", None)
                .status_class()
                .contains("orange")
        );
    }

    #[test]
    fn test_status_class_unknown_falls_back_to_gray() {
        assert!(make_item("whatever", None).status_class().contains("gray"));
    }

    // ---- status_label ----

    #[test]
    fn test_status_label_pending() {
        assert_eq!(make_item("pending", None).status_label(), "Pending");
    }

    #[test]
    fn test_status_label_approved() {
        assert_eq!(make_item("approved", None).status_label(), "Approved");
    }

    #[test]
    fn test_status_label_rejected() {
        assert_eq!(make_item("rejected", None).status_label(), "Rejected");
    }

    #[test]
    fn test_status_label_revoked() {
        assert_eq!(make_item("revoked", None).status_label(), "Revoked");
    }

    #[test]
    fn test_is_approved_false_for_revoked_hides_connect_button() {
        // The Connect button in my_requests.html gates on
        // `is_approved()`; a revoked grant must never render it.
        assert!(!make_item("revoked", None).is_approved());
    }

    #[test]
    fn test_status_label_expired() {
        assert_eq!(make_item("expired", None).status_label(), "Expired");
    }

    #[test]
    fn test_status_label_phantom_consumed_shows_unknown() {
        assert_eq!(make_item("consumed", None).status_label(), "Unknown");
    }

    #[test]
    fn test_status_label_active_shows_connected() {
        assert_eq!(make_item("active", None).status_label(), "Connected");
    }

    #[test]
    fn test_status_label_disconnected_shows_completed() {
        assert_eq!(make_item("disconnected", None).status_label(), "Completed");
    }

    #[test]
    fn test_status_label_terminated() {
        assert_eq!(make_item("terminated", None).status_label(), "Terminated");
    }

    #[test]
    fn test_status_label_unknown() {
        assert_eq!(make_item("xyz", None).status_label(), "Unknown");
    }

    // ---- is_pending / is_approved ----

    #[test]
    fn test_is_pending_true() {
        assert!(make_item("pending", None).is_pending());
    }

    #[test]
    fn test_is_pending_false_for_approved() {
        assert!(!make_item("approved", None).is_pending());
    }

    #[test]
    fn test_is_approved_true() {
        assert!(make_item("approved", None).is_approved());
    }

    #[test]
    fn test_is_approved_false_for_pending() {
        assert!(!make_item("pending", None).is_approved());
    }

    // ---- duration_display ----

    #[test]
    fn test_duration_display_none_returns_unlimited() {
        assert_eq!(make_item("pending", None).duration_display(), "Unlimited");
    }

    #[test]
    fn test_duration_display_exact_hours() {
        assert_eq!(make_item("approved", Some(3600)).duration_display(), "1h");
        assert_eq!(make_item("approved", Some(7200)).duration_display(), "2h");
        assert_eq!(make_item("approved", Some(28800)).duration_display(), "8h");
    }

    #[test]
    fn test_duration_display_minutes() {
        assert_eq!(
            make_item("approved", Some(1800)).duration_display(),
            "30min"
        );
        assert_eq!(make_item("approved", Some(900)).duration_display(), "15min");
        assert_eq!(make_item("approved", Some(60)).duration_display(), "1min");
    }

    #[test]
    fn test_duration_display_mixed_falls_back_to_minutes() {
        assert_eq!(
            make_item("approved", Some(5400)).duration_display(),
            "90min"
        );
    }

    #[test]
    fn test_duration_display_zero_returns_zero_min() {
        assert_eq!(make_item("approved", Some(0)).duration_display(), "0min");
    }

    // ---- struct fields ----

    #[test]
    fn test_item_clone() {
        let item = make_item("pending", Some(3600));
        let cloned = item.clone();
        assert_eq!(item.uuid, cloned.uuid);
        assert_eq!(item.max_session_duration, cloned.max_session_duration);
    }

    #[test]
    fn test_item_optional_fields() {
        let mut item = make_item("pending", None);
        item.justification = None;
        item.approved_at = None;
        item.approved_by = None;
        assert!(item.justification.is_none());
        assert!(item.approved_at.is_none());
        assert!(item.approved_by.is_none());
    }

    #[test]
    fn test_item_with_approval_info() {
        let mut item = make_item("approved", Some(7200));
        item.approved_at = Some("Mar 30, 2026 11:00".to_string());
        item.approved_by = Some("admin".to_string());
        assert_eq!(item.approved_at.as_deref(), Some("Mar 30, 2026 11:00"));
        assert_eq!(item.approved_by.as_deref(), Some("admin"));
    }

    // ---- Connect control of an approved request ----

    fn render_requests(
        requests: Vec<MyRequestItem>,
        require_justification: bool,
        iacs_connect_allowed: bool,
        user_has_active_ews: bool,
    ) -> String {
        let template = MyRequestsTemplate {
            title: "My Requests".to_string(),
            user: None,
            vauban: crate::templates::base::VaubanConfig {
                brand_name: "VAUBAN".to_string(),
                brand_logo: None,
                theme: "dark".to_string(),
                ..Default::default()
            },
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
            requests,
            pagination: None,
            iacs_visible: false,
            require_justification,
            iacs_connect_allowed,
            user_has_active_ews,
            iacs_request_allowed: false,
            ews_items: Vec::new(),
            csrf_token: "tk".to_string(),
            search: None,
            status_filter: None,
            statuses: crate::services::status_vocab::MY_REQUESTS.options(),
            ews_search: None,
            ews_state_filter: None,
        };
        template.render().expect("template should render")
    }

    fn approved(asset_type: &str) -> MyRequestItem {
        let mut item = make_item("approved", None);
        item.asset_type = asset_type.to_string();
        item
    }

    #[test]
    fn test_connect_posts_to_the_asset_connect_endpoint_per_type() {
        for (asset_type, endpoint) in [("ssh", "connect"), ("rdp", "connect-rdp")] {
            let html = render_requests(vec![approved(asset_type)], false, false, false);
            assert!(
                html.contains(&format!(r#"hx-post="/assets/asset-uuid-1/{endpoint}""#)),
                "{asset_type}: Connect must post to /assets/<asset uuid>/{endpoint}"
            );
            assert!(
                !html.contains(r#"@click="$store.justificationModal.open("#),
                "{asset_type}: no modal when nothing is asked"
            );
        }
    }

    /// The path carries the asset's UUID. The request's UUID in an asset
    /// path was the defect: `/assets/{uuid}` is a constant 410.
    #[test]
    fn test_connect_never_puts_the_request_uuid_in_an_asset_path() {
        for (justification, mfa) in [(false, false), (true, false), (false, true)] {
            let mut item = approved("ssh");
            item.require_mfa = mfa;
            let html = render_requests(vec![item], justification, false, false);
            assert!(!html.contains("/assets/uuid-123"));
            assert!(!html.contains(r#"href="/assets/"#));
        }
    }

    #[test]
    fn test_connect_opens_the_justification_modal_when_required() {
        let html = render_requests(vec![approved("ssh")], true, false, false);
        assert!(
            html.contains(
                "$store.justificationModal.open(&#39;asset-uuid-1&#39;, &#39;ssh&#39;, false, true)"
            ) || html
                .contains("$store.justificationModal.open('asset-uuid-1', 'ssh', false, true)")
        );
        assert!(!html.contains(r#"hx-post="/assets/asset-uuid-1/connect""#));
    }

    #[test]
    fn test_connect_opens_the_code_modal_when_the_rule_requires_mfa() {
        let mut item = approved("rdp");
        item.require_mfa = true;
        let html = render_requests(vec![item], false, false, false);
        assert!(
            html.contains("$store.justificationModal.open('asset-uuid-1', 'rdp', true, false)")
        );
    }

    #[test]
    fn test_connect_for_mcp_always_goes_through_the_modal() {
        let html = render_requests(vec![approved("mcp")], false, false, false);
        assert!(
            html.contains("$store.justificationModal.open('asset-uuid-1', 'mcp', false, true)")
        );
    }

    #[test]
    fn test_iacs_connect_follows_the_three_way_gate() {
        let iacs = || {
            let mut item = approved("iacs_modbus");
            item.is_iacs = true;
            item
        };
        let form = r#"hx-post="/assets/asset-uuid-1/connect-iacs""#;

        let html = render_requests(vec![iacs()], false, true, true);
        assert!(html.contains(form), "allowed + workstation: tunnel form");

        let html = render_requests(vec![iacs()], false, true, false);
        assert!(!html.contains(form));
        assert!(
            html.contains(r#"href="/iacs/onboard""#),
            "no workstation: onboard link"
        );

        let html = render_requests(vec![iacs()], true, false, true);
        assert!(!html.contains(form), "not allowed: nothing");
        assert!(!html.contains(r#"href="/iacs/onboard""#));
        assert!(!html.contains(r#"@click="$store.justificationModal.open("#));
    }

    #[test]
    fn test_only_an_approved_request_carries_a_connect_control() {
        for status in ["pending", "rejected", "revoked", "expired", "active"] {
            let html = render_requests(vec![make_item(status, None)], true, true, true);
            assert!(
                !html.contains(r#"data-testid="connect-uuid-123""#),
                "{status}: no Connect control"
            );
        }
        let html = render_requests(vec![make_item("approved", None)], false, false, false);
        assert!(html.contains(r#"data-testid="connect-uuid-123""#));
    }

    /// The Connect control drives the two modals of the asset list; the
    /// page must carry them, once.
    #[test]
    fn test_page_includes_both_connect_modals_once() {
        let html = render_requests(vec![approved("ssh"), approved("rdp")], true, false, false);
        assert_eq!(html.matches(r#"id="justification-modal-text""#).count(), 1);
        assert!(html.contains("$store.accessModal.show = false"));
    }

    // ---- template render ----

    #[test]
    fn test_my_requests_template_renders_with_items() {
        use crate::templates::base::{UserContext, VaubanConfig};

        let template = MyRequestsTemplate {
            title: "My Requests".to_string(),
            user: Some(UserContext {
                uuid: "u1".to_string(),
                username: "alice".to_string(),
                display_name: "Alice".to_string(),
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
            requests: vec![
                make_item("pending", Some(3600)),
                make_item("approved", None),
            ],
            pagination: None,
            iacs_visible: false,
            require_justification: false,
            iacs_connect_allowed: false,
            user_has_active_ews: false,
            iacs_request_allowed: false,
            ews_items: Vec::new(),
            csrf_token: "tk".to_string(),
            search: None,
            status_filter: None,
            statuses: crate::services::status_vocab::MY_REQUESTS.options(),
            ews_search: None,
            ews_state_filter: None,
        };

        let html = template.render().expect("template should render");
        assert!(html.contains("1h"), "should show 1h duration");
        assert!(
            html.contains(r#"hx-post="/assets/asset-uuid-1/connect""#),
            "approved request must carry the direct Connect form"
        );
        assert!(
            !html.contains(r#"href="/assets/"#),
            "no link to the removed /assets/{{uuid}} page"
        );
        assert!(html.contains("Unlimited"), "should show Unlimited");
        assert!(
            html.contains("ws-connect=\"/ws/notifications\""),
            "should have ws-connect"
        );
        assert!(html.contains("jit-notification"), "should have OOB target");
        for event in [
            "request_approved",
            "request_rejected",
            "request_expired",
            "request_revoked",
            "request_duration_updated",
        ] {
            assert!(html.contains(event), "should filter on {event}");
        }
    }

    #[test]
    fn test_my_requests_template_renders_all_statuses() {
        use crate::templates::base::{UserContext, VaubanConfig};

        let statuses = [
            ("pending", "Pending"),
            ("approved", "Approved"),
            ("rejected", "Rejected"),
            ("revoked", "Revoked"),
            ("expired", "Expired"),
            ("active", "Connected"),
            ("disconnected", "Completed"),
            ("terminated", "Terminated"),
        ];

        for (status, label) in &statuses {
            let template = MyRequestsTemplate {
                title: "My Requests".to_string(),
                user: Some(UserContext {
                    uuid: "u1".to_string(),
                    username: "alice".to_string(),
                    display_name: "Alice".to_string(),
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
                requests: vec![make_item(status, Some(3600))],
                pagination: None,
                iacs_visible: false,
                require_justification: false,
                iacs_connect_allowed: false,
                user_has_active_ews: false,
                iacs_request_allowed: false,
                ews_items: Vec::new(),
                csrf_token: "tk".to_string(),
                search: None,
                status_filter: None,
                statuses: crate::services::status_vocab::MY_REQUESTS.options(),
                ews_search: None,
                ews_state_filter: None,
            };

            let html = template
                .render()
                .unwrap_or_else(|_| panic!("template should render for status '{}'", status));
            assert!(
                html.contains(label),
                "status '{}' should render label '{}' in template",
                status,
                label
            );
        }
    }

    #[test]
    fn test_my_requests_template_renders_empty() {
        use crate::templates::base::{UserContext, VaubanConfig};

        let template = MyRequestsTemplate {
            title: "My Requests".to_string(),
            user: Some(UserContext {
                uuid: "u1".to_string(),
                username: "alice".to_string(),
                display_name: "Alice".to_string(),
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
            requests: Vec::new(),
            pagination: None,
            iacs_visible: false,
            require_justification: false,
            iacs_connect_allowed: false,
            user_has_active_ews: false,
            iacs_request_allowed: false,
            ews_items: Vec::new(),
            csrf_token: "tk".to_string(),
            search: None,
            status_filter: None,
            statuses: crate::services::status_vocab::MY_REQUESTS.options(),
            ews_search: None,
            ews_state_filter: None,
        };

        let html = template.render().expect("template should render");
        assert!(
            html.contains("No access requests"),
            "should show empty state"
        );
    }

    fn make_template(
        items: Vec<MyRequestItem>,
        pagination: Option<Pagination>,
    ) -> MyRequestsTemplate {
        use crate::templates::base::{UserContext, VaubanConfig};
        MyRequestsTemplate {
            title: "My Requests".to_string(),
            user: Some(UserContext {
                uuid: "u1".to_string(),
                username: "alice".to_string(),
                display_name: "Alice".to_string(),
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
            requests: items,
            pagination,
            iacs_visible: false,
            require_justification: false,
            iacs_connect_allowed: false,
            user_has_active_ews: false,
            iacs_request_allowed: false,
            ews_items: Vec::new(),
            csrf_token: "tk".to_string(),
            search: None,
            status_filter: None,
            statuses: crate::services::status_vocab::MY_REQUESTS.options(),
            ews_search: None,
            ews_state_filter: None,
        }
    }

    fn make_pg(current_page: i32, total_pages: i32, total_items: i32) -> Pagination {
        let has_previous = current_page > 1;
        let has_next = current_page < total_pages;
        let start = ((current_page - 1) * 30) + 1;
        let end = (current_page * 30).min(total_items);
        Pagination {
            current_page,
            total_pages,
            total_items,
            items_per_page: 30,
            has_previous,
            has_next,
            start_index: start,
            end_index: end,
        }
    }

    // ---- pagination rendering ----

    #[test]
    fn test_pagination_renders_on_first_page() {
        let pg = make_pg(1, 3, 75);
        let items: Vec<MyRequestItem> = (0..30).map(|_| make_item("pending", Some(3600))).collect();
        let template = make_template(items, Some(pg));
        let html = template.render().expect("render");
        assert!(html.contains("Showing"), "should show pagination counter");
        assert!(
            html.contains("of <span class=\"font-medium\">75</span>"),
            "should show total"
        );
        assert!(
            !html.contains("First page"),
            "first page should not have First link (sr-only text)"
        );
        assert!(html.contains("Next page"), "should have Next link");
        assert!(html.contains("Last page"), "should have Last link");
    }

    #[test]
    fn test_pagination_renders_on_middle_page() {
        let pg = make_pg(2, 3, 75);
        let items: Vec<MyRequestItem> = (0..30).map(|_| make_item("approved", None)).collect();
        let template = make_template(items, Some(pg));
        let html = template.render().expect("render");
        assert!(html.contains("First page"), "should have First link");
        assert!(html.contains("Previous page"), "should have Previous link");
        assert!(html.contains("Next page"), "should have Next link");
        assert!(html.contains("Last page"), "should have Last link");
        assert!(html.contains("page=1"), "should link to page 1");
        assert!(html.contains("page=3"), "should link to page 3");
    }

    #[test]
    fn test_pagination_renders_on_last_page() {
        let pg = make_pg(3, 3, 75);
        let items: Vec<MyRequestItem> = (0..15).map(|_| make_item("expired", Some(1800))).collect();
        let template = make_template(items, Some(pg));
        let html = template.render().expect("render");
        assert!(html.contains("First page"), "should have First link");
        assert!(html.contains("Previous page"), "should have Previous link");
        assert!(
            !html.contains("Next page"),
            "last page should not have Next"
        );
        assert!(
            !html.contains("Last page"),
            "last page should not have Last"
        );
    }

    #[test]
    fn test_pagination_counter_accuracy() {
        let pg = make_pg(2, 3, 75);
        let items: Vec<MyRequestItem> = (0..30).map(|_| make_item("pending", None)).collect();
        let template = make_template(items, Some(pg));
        let html = template.render().expect("render");
        assert!(html.contains(">31</span>"), "start should be 31");
        assert!(html.contains(">60</span>"), "end should be 60");
        assert!(html.contains(">75</span>"), "total should be 75");
    }

    #[test]
    fn test_pagination_current_page_highlighted() {
        let pg = make_pg(2, 4, 100);
        let items: Vec<MyRequestItem> = (0..30).map(|_| make_item("pending", None)).collect();
        let template = make_template(items, Some(pg));
        let html = template.render().expect("render");
        assert!(
            html.contains("aria-current=\"page\""),
            "current page should have aria-current"
        );
    }

    #[test]
    fn test_pagination_mobile_buttons() {
        let pg = make_pg(2, 3, 75);
        let items: Vec<MyRequestItem> = (0..30).map(|_| make_item("pending", None)).collect();
        let template = make_template(items, Some(pg));
        let html = template.render().expect("render");
        assert!(html.contains("sm:hidden"), "should have mobile container");
    }

    #[test]
    fn test_no_pagination_without_items() {
        let template = make_template(Vec::new(), None);
        let html = template.render().expect("render");
        assert!(!html.contains("Showing"), "no pagination for empty list");
        assert!(
            html.contains("No access requests"),
            "should show empty state"
        );
    }

    #[test]
    fn test_pagination_single_page_no_nav_buttons() {
        let pg = make_pg(1, 1, 5);
        let items: Vec<MyRequestItem> = (0..5).map(|_| make_item("pending", None)).collect();
        let template = make_template(items, Some(pg));
        let html = template.render().expect("render");
        assert!(html.contains("Showing"), "should still show counter");
        assert!(
            !html.contains("Next page"),
            "single page should not have Next"
        );
        assert!(
            !html.contains("Previous page"),
            "single page should not have Previous"
        );
    }
}

#[derive(Template)]
#[template(path = "sessions/my_requests.html")]
pub struct MyRequestsTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub requests: Vec<MyRequestItem>,
    pub pagination: Option<Pagination>,
    /// IACS / EWS section.
    ///
    /// `iacs_visible` is the kill-switch + Casbin gate (`iacs_read`)
    /// pre-resolved by the handler so the template stays a pure
    /// projection. When `false`, the entire "My EWS" block is
    /// suppressed -- including the heading -- and `ews_items` is
    /// guaranteed empty by the handler.
    pub iacs_visible: bool,
    /// `[security] require_justification`: the Connect control of an
    /// approved request opens the justification modal, as on the list.
    pub require_justification: bool,
    /// Casbin + kill-switch (`assets:connect_iacs`): without it the IACS
    /// Connect control is not rendered at all.
    pub iacs_connect_allowed: bool,
    /// The caller owns an active Engineering Workstation.
    pub user_has_active_ews: bool,
    /// True when the caller may submit / edit / cancel / auto-offboard
    /// (`iacs_request`). Drives the "Onboard EWS" CTA and the per-row
    /// owner-actionable buttons.
    pub iacs_request_allowed: bool,
    /// Per-user EWS rows (pending requests AND approved EWS folded
    /// into a single ordered list, newest first).
    pub ews_items: Vec<crate::templates::iacs::MyEwsItem>,
    /// CSRF token reused by the inlined cancel / offboard-self forms.
    pub csrf_token: String,
    /// Live-filter needles (issue #28 pattern), independent per tab:
    /// `search` / `status_filter` drive the Access list,
    /// `ews_search` / `ews_state_filter` drive the EWS list.
    pub search: Option<String>,
    pub status_filter: Option<String>,
    /// `(value, label)` couples of the Access status select, derived
    /// from `status_vocab::MY_REQUESTS` (single source of truth).
    pub statuses: Vec<(String, String)>,
    pub ews_search: Option<String>,
    pub ews_state_filter: Option<String>,
}

impl MyRequestsTemplate {
    /// Whether an Access-tab filter is active (picks the "no match"
    /// empty state over the onboarding one).
    #[must_use]
    pub fn has_filters(&self) -> bool {
        self.search.is_some() || self.status_filter.is_some()
    }

    /// Whether an EWS-tab filter is active.
    #[must_use]
    pub fn has_ews_filters(&self) -> bool {
        self.ews_search.is_some() || self.ews_state_filter.is_some()
    }

    /// `&key=value` suffix for the Access pagination links so
    /// switching page never drops the filters (either tab's).
    #[must_use]
    pub fn filter_query_suffix(&self) -> String {
        crate::services::list_filters::query_suffix(&[
            ("search", &self.search),
            ("status", &self.status_filter),
            ("ews_search", &self.ews_search),
            ("ews_state", &self.ews_state_filter),
        ])
    }
}
