//! VAUBAN Web - Utility functions.
//!
//! Common utilities shared across the application.

/// Format duration in seconds to human-readable string.
///
/// Uses a progressive format showing only relevant time units:
/// - Less than 1 minute: "Xs"
/// - Less than 1 hour: "Xm Ys"
/// - Less than 1 day: "Xh Ym"
/// - 1 day or more: "Xj Yh Zm"
///
/// # Examples
///
/// ```
/// use vauban_web::utils::format_duration;
///
/// assert_eq!(format_duration(45), "45s");
/// assert_eq!(format_duration(125), "2m 5s");
/// assert_eq!(format_duration(3725), "1h 2m");
/// assert_eq!(format_duration(90061), "1j 1h 1m");
/// ```
pub fn format_duration(seconds: i64) -> String {
    const MINUTE: i64 = 60;
    const HOUR: i64 = 3600;
    const DAY: i64 = 86400;

    if seconds < 0 {
        return "0s".to_string();
    }

    if seconds < MINUTE {
        format!("{}s", seconds)
    } else if seconds < HOUR {
        let mins = seconds / MINUTE;
        let secs = seconds % MINUTE;
        format!("{}m {}s", mins, secs)
    } else if seconds < DAY {
        let hours = seconds / HOUR;
        let mins = (seconds % HOUR) / MINUTE;
        format!("{}h {}m", hours, mins)
    } else {
        let days = seconds / DAY;
        let hours = (seconds % DAY) / HOUR;
        let mins = (seconds % HOUR) / MINUTE;
        format!("{}j {}h {}m", days, hours, mins)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== Seconds Format Tests ====================

    #[test]
    fn test_format_duration_zero() {
        assert_eq!(format_duration(0), "0s");
    }

    #[test]
    fn test_format_duration_seconds_only() {
        assert_eq!(format_duration(1), "1s");
        assert_eq!(format_duration(30), "30s");
        assert_eq!(format_duration(59), "59s");
    }

    #[test]
    fn test_format_duration_negative() {
        assert_eq!(format_duration(-1), "0s");
        assert_eq!(format_duration(-100), "0s");
    }

    // ==================== Minutes Format Tests ====================

    #[test]
    fn test_format_duration_exact_minute() {
        assert_eq!(format_duration(60), "1m 0s");
    }

    #[test]
    fn test_format_duration_minutes_with_seconds() {
        assert_eq!(format_duration(90), "1m 30s");
        assert_eq!(format_duration(125), "2m 5s");
        assert_eq!(format_duration(3599), "59m 59s");
    }

    // ==================== Hours Format Tests ====================

    #[test]
    fn test_format_duration_exact_hour() {
        assert_eq!(format_duration(3600), "1h 0m");
    }

    #[test]
    fn test_format_duration_hours_with_minutes() {
        assert_eq!(format_duration(3660), "1h 1m");
        assert_eq!(format_duration(3725), "1h 2m");
        assert_eq!(format_duration(7200), "2h 0m");
        assert_eq!(format_duration(7325), "2h 2m");
    }

    #[test]
    fn test_format_duration_max_hours() {
        // 23h 59m = 86340 seconds
        assert_eq!(format_duration(86340), "23h 59m");
        assert_eq!(format_duration(86399), "23h 59m");
    }

    // ==================== Days Format Tests ====================

    #[test]
    fn test_format_duration_exact_day() {
        assert_eq!(format_duration(86400), "1j 0h 0m");
    }

    #[test]
    fn test_format_duration_days_with_hours_minutes() {
        // 1 day + 1 hour + 1 minute = 90060 seconds
        assert_eq!(format_duration(90060), "1j 1h 1m");
        // 1 day + 1 hour + 1 minute + 1 second = 90061 seconds
        assert_eq!(format_duration(90061), "1j 1h 1m");
    }

    #[test]
    fn test_format_duration_multiple_days() {
        // 3 days + 5 hours + 20 minutes
        let seconds = 3 * 86400 + 5 * 3600 + 20 * 60;
        assert_eq!(format_duration(seconds), "3j 5h 20m");
    }

    #[test]
    fn test_format_duration_week() {
        // 7 days
        assert_eq!(format_duration(7 * 86400), "7j 0h 0m");
    }

    #[test]
    fn test_format_duration_long_session() {
        // 30 days + 12 hours + 45 minutes
        let seconds = 30 * 86400 + 12 * 3600 + 45 * 60;
        assert_eq!(format_duration(seconds), "30j 12h 45m");
    }

    // ==================== Boundary Tests ====================

    #[test]
    fn test_format_duration_boundary_minute() {
        assert_eq!(format_duration(59), "59s");
        assert_eq!(format_duration(60), "1m 0s");
    }

    #[test]
    fn test_format_duration_boundary_hour() {
        assert_eq!(format_duration(3599), "59m 59s");
        assert_eq!(format_duration(3600), "1h 0m");
    }

    #[test]
    fn test_format_duration_boundary_day() {
        assert_eq!(format_duration(86399), "23h 59m");
        assert_eq!(format_duration(86400), "1j 0h 0m");
    }

    // ==================== Constants Tests ====================

    #[test]
    fn test_constants_are_correct() {
        const MINUTE: i64 = 60;
        const HOUR: i64 = 3600;
        const DAY: i64 = 86400;

        assert_eq!(HOUR, MINUTE * 60);
        assert_eq!(DAY, HOUR * 24);
    }
}
