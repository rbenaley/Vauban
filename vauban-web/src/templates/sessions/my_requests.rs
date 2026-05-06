use crate::templates::accounts::user_list::Pagination;
use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};
/// VAUBAN Web - My access requests template.
use askama::Template;

/// User access request item.
#[derive(Debug, Clone)]
pub struct MyRequestItem {
    pub uuid: String,
    pub asset_name: String,
    pub asset_hostname: String,
    pub asset_type: String,
    pub session_type: String,
    pub status: String,
    pub justification: Option<String>,
    pub created_at: String,
    pub approved_at: Option<String>,
    pub approved_by: Option<String>,
    pub max_session_duration: Option<i32>,
}

impl MyRequestItem {
    pub fn status_class(&self) -> &str {
        super::session_status_class(&self.status)
    }

    /// User-friendly label for display (avoids raw DB statuses like "consumed").
    pub fn status_label(&self) -> &str {
        match self.status.as_str() {
            "pending" => "Pending",
            "approved" => "Approved",
            "rejected" => "Rejected",
            "expired" => "Expired",
            "consumed" | "active" => "Connected",
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
    fn test_status_class_expired() {
        assert!(make_item("expired", None).status_class().contains("gray"));
    }

    #[test]
    fn test_status_class_consumed() {
        assert!(make_item("consumed", None).status_class().contains("blue"));
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
    fn test_status_label_expired() {
        assert_eq!(make_item("expired", None).status_label(), "Expired");
    }

    #[test]
    fn test_status_label_consumed_shows_connected() {
        assert_eq!(make_item("consumed", None).status_label(), "Connected");
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
            iacs_request_allowed: false,
            ews_items: Vec::new(),
            csrf_token: "tk".to_string(),
        };

        let html = template.render().expect("template should render");
        assert!(html.contains("1h"), "should show 1h duration");
        assert!(html.contains("Unlimited"), "should show Unlimited");
        assert!(
            html.contains("ws-connect=\"/ws/notifications\""),
            "should have ws-connect"
        );
        assert!(html.contains("jit-notification"), "should have OOB target");
        assert!(
            html.contains("request_approved"),
            "should filter on request_approved"
        );
    }

    #[test]
    fn test_my_requests_template_renders_all_statuses() {
        use crate::templates::base::{UserContext, VaubanConfig};

        let statuses = [
            ("pending", "Pending"),
            ("approved", "Approved"),
            ("rejected", "Rejected"),
            ("expired", "Expired"),
            ("consumed", "Connected"),
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
                iacs_request_allowed: false,
                ews_items: Vec::new(),
                csrf_token: "tk".to_string(),
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
            iacs_request_allowed: false,
            ews_items: Vec::new(),
            csrf_token: "tk".to_string(),
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
            iacs_request_allowed: false,
            ews_items: Vec::new(),
            csrf_token: "tk".to_string(),
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
    /// True when the caller may submit / edit / cancel / auto-offboard
    /// (`iacs_request`). Drives the "Onboard EWS" CTA and the per-row
    /// owner-actionable buttons.
    pub iacs_request_allowed: bool,
    /// Per-user EWS rows (pending requests AND approved EWS folded
    /// into a single ordered list, newest first).
    pub ews_items: Vec<crate::templates::iacs::MyEwsItem>,
    /// CSRF token reused by the inlined cancel / offboard-self forms.
    pub csrf_token: String,
}
