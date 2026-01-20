/// VAUBAN Web - Active sessions widget template.
use askama::Template;

#[derive(Debug, Clone)]
pub struct ActiveSessionItem {
    pub id: i32,
    pub asset_name: String,
    pub asset_hostname: String,
    pub session_type: String,
    /// Formatted duration string (e.g., "5m 30s", "2h 15m", "1j 3h 20m").
    pub duration: Option<String>,
}

#[derive(Template)]
#[template(path = "dashboard/widgets/active_sessions.html")]
pub struct ActiveSessionsWidget {
    pub sessions: Vec<ActiveSessionItem>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_session_item() -> ActiveSessionItem {
        ActiveSessionItem {
            id: 1,
            asset_name: "Test Server".to_string(),
            asset_hostname: "test.example.com".to_string(),
            session_type: "ssh".to_string(),
            duration: Some("1h 0m".to_string()),
        }
    }

    #[test]
    fn test_active_session_item_creation() {
        let item = create_test_session_item();
        assert_eq!(item.id, 1);
        assert_eq!(item.asset_name, "Test Server");
    }

    #[test]
    fn test_active_session_item_without_duration() {
        let mut item = create_test_session_item();
        item.duration = None;
        assert!(item.duration.is_none());
    }

    #[test]
    fn test_active_session_item_clone() {
        let item = create_test_session_item();
        let cloned = item.clone();
        assert_eq!(item.id, cloned.id);
        assert_eq!(item.session_type, cloned.session_type);
    }

    #[test]
    fn test_active_sessions_widget_creation() {
        let widget = ActiveSessionsWidget {
            sessions: vec![create_test_session_item()],
        };
        assert_eq!(widget.sessions.len(), 1);
    }

    #[test]
    fn test_active_sessions_widget_empty() {
        let widget = ActiveSessionsWidget {
            sessions: Vec::new(),
        };
        assert!(widget.sessions.is_empty());
    }

    #[test]
    fn test_active_sessions_widget_renders() {
        let widget = ActiveSessionsWidget {
            sessions: vec![create_test_session_item()],
        };
        let result = widget.render();
        assert!(result.is_ok());
    }
}
