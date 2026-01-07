/// VAUBAN Web - Recent activity widget template.
use askama::Template;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct ActivityItem {
    pub user: String,
    pub action: String,
    pub asset: Option<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Template)]
#[template(path = "dashboard/widgets/recent_activity.html")]
pub struct RecentActivityWidget {
    pub activities: Vec<ActivityItem>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_activity_item() -> ActivityItem {
        ActivityItem {
            user: "testuser".to_string(),
            action: "login".to_string(),
            asset: Some("Test Server".to_string()),
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn test_activity_item_creation() {
        let item = create_test_activity_item();
        assert_eq!(item.user, "testuser");
        assert_eq!(item.action, "login");
    }

    #[test]
    fn test_activity_item_without_asset() {
        let mut item = create_test_activity_item();
        item.asset = None;
        assert!(item.asset.is_none());
    }

    #[test]
    fn test_activity_item_clone() {
        let item = create_test_activity_item();
        let cloned = item.clone();
        assert_eq!(item.user, cloned.user);
        assert_eq!(item.action, cloned.action);
    }

    #[test]
    fn test_recent_activity_widget_creation() {
        let widget = RecentActivityWidget {
            activities: vec![create_test_activity_item()],
        };
        assert_eq!(widget.activities.len(), 1);
    }

    #[test]
    fn test_recent_activity_widget_empty() {
        let widget = RecentActivityWidget {
            activities: Vec::new(),
        };
        assert!(widget.activities.is_empty());
    }

    #[test]
    fn test_recent_activity_widget_renders() {
        let widget = RecentActivityWidget {
            activities: vec![create_test_activity_item()],
        };
        let result = widget.render();
        assert!(result.is_ok());
    }
}
