#[allow(unused_imports)]
use crate::utils::filters;
/// VAUBAN Web - Recent activity widget template.
use askama::Template;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A recent-activity row. `timestamp` is carried as a raw
/// `DateTime<Utc>` and rendered in the viewer's browser timezone at
/// the last moment via the `local` filter. `Serialize`/`Deserialize`
/// let the dashboard task broadcast the raw rows on the
/// `RecentActivity` channel so each WS connection re-renders them in
/// its own timezone (per-connection rendering).
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub tz: chrono_tz::Tz,
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
            tz: chrono_tz::Tz::UTC,
        };
        assert_eq!(widget.activities.len(), 1);
    }

    #[test]
    fn test_recent_activity_widget_empty() {
        let widget = RecentActivityWidget {
            activities: Vec::new(),
            tz: chrono_tz::Tz::UTC,
        };
        assert!(widget.activities.is_empty());
    }

    #[test]
    fn test_recent_activity_widget_renders() {
        let widget = RecentActivityWidget {
            activities: vec![create_test_activity_item()],
            tz: chrono_tz::Tz::UTC,
        };
        let result = widget.render();
        assert!(result.is_ok());
    }
}
