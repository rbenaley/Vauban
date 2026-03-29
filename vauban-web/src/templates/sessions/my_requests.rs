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
        match self.status.as_str() {
            "pending" => "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/50 dark:text-yellow-300",
            "approved" => "bg-green-100 text-green-800 dark:bg-green-900/50 dark:text-green-300",
            "rejected" => "bg-red-100 text-red-800 dark:bg-red-900/50 dark:text-red-300",
            "expired" => "bg-gray-100 text-gray-800 dark:bg-gray-900/50 dark:text-gray-300",
            _ => "bg-gray-100 text-gray-800 dark:bg-gray-900/50 dark:text-gray-300",
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
    fn test_status_class_unknown_falls_back_to_gray() {
        assert!(make_item("whatever", None).status_class().contains("gray"));
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
        assert_eq!(make_item("approved", Some(1800)).duration_display(), "30min");
        assert_eq!(make_item("approved", Some(900)).duration_display(), "15min");
        assert_eq!(make_item("approved", Some(60)).duration_display(), "1min");
    }

    #[test]
    fn test_duration_display_mixed_falls_back_to_minutes() {
        assert_eq!(make_item("approved", Some(5400)).duration_display(), "90min");
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
            },
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
            requests: vec![
                make_item("pending", Some(3600)),
                make_item("approved", None),
            ],
        };

        let html = template.render().expect("template should render");
        assert!(html.contains("1h"), "should show 1h duration");
        assert!(html.contains("Unlimited"), "should show Unlimited");
        assert!(html.contains("ws-connect=\"/ws/notifications\""), "should have ws-connect");
        assert!(html.contains("jit-notification"), "should have OOB target");
        assert!(html.contains("request_approved"), "should filter on request_approved");
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
            },
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
            requests: Vec::new(),
        };

        let html = template.render().expect("template should render");
        assert!(html.contains("No access requests"), "should show empty state");
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
}
