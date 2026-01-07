/// VAUBAN Web - Stats widget template.
use askama::Template;

#[derive(Debug, Clone)]
pub struct StatsData {
    pub active_sessions: i32,
    pub today_sessions: i32,
    pub week_sessions: i32,
}

#[derive(Template)]
#[template(path = "dashboard/widgets/stats.html")]
pub struct StatsWidget {
    pub stats: StatsData,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_stats_data() -> StatsData {
        StatsData {
            active_sessions: 5,
            today_sessions: 25,
            week_sessions: 150,
        }
    }

    #[test]
    fn test_stats_data_creation() {
        let stats = create_test_stats_data();
        assert_eq!(stats.active_sessions, 5);
        assert_eq!(stats.today_sessions, 25);
        assert_eq!(stats.week_sessions, 150);
    }

    #[test]
    fn test_stats_data_zero() {
        let stats = StatsData {
            active_sessions: 0,
            today_sessions: 0,
            week_sessions: 0,
        };
        assert_eq!(stats.active_sessions, 0);
    }

    #[test]
    fn test_stats_data_clone() {
        let stats = create_test_stats_data();
        let cloned = stats.clone();
        assert_eq!(stats.active_sessions, cloned.active_sessions);
        assert_eq!(stats.week_sessions, cloned.week_sessions);
    }

    #[test]
    fn test_stats_widget_creation() {
        let widget = StatsWidget {
            stats: create_test_stats_data(),
        };
        assert_eq!(widget.stats.active_sessions, 5);
    }

    #[test]
    fn test_stats_widget_renders() {
        let widget = StatsWidget {
            stats: create_test_stats_data(),
        };
        let result = widget.render();
        assert!(result.is_ok());
    }
}
