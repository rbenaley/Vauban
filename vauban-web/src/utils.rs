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

/// Maximum allowed session duration (24 hours).
pub const MAX_DURATION_SECONDS: i32 = 86_400;

/// Default session duration for new access rules (2 hours).
pub const DEFAULT_DURATION_SECONDS: i32 = 7_200;

/// Convert a (value, unit) pair into seconds.
///
/// Returns `Ok(None)` when no value is provided (keep existing / unlimited),
/// `Ok(Some(seconds))` for a valid input, or `Err` for invalid input.
pub fn resolve_duration_seconds(
    value: Option<i32>,
    unit: Option<&str>,
) -> Result<Option<i32>, &'static str> {
    let value = match value {
        Some(v) => v,
        None => return Ok(None),
    };

    if value < 1 {
        return Err("Duration must be at least 1");
    }

    let unit = unit.unwrap_or("minutes");

    let seconds = match unit {
        "hours" => value.checked_mul(3600).ok_or("Duration overflow")?,
        "minutes" => value.checked_mul(60).ok_or("Duration overflow")?,
        _ => return Err("Invalid duration unit"),
    };

    if seconds < 60 {
        return Err("Duration must be at least 1 minute");
    }
    if seconds > MAX_DURATION_SECONDS {
        return Err("Duration cannot exceed 24 hours");
    }

    Ok(Some(seconds))
}

/// Human-readable duration (e.g. "2h", "30min", "Unlimited").
pub fn duration_display(secs: Option<i32>) -> String {
    match secs {
        None => "Unlimited".to_string(),
        Some(s) => {
            if s >= 3600 && s % 3600 == 0 {
                format!("{}h", s / 3600)
            } else {
                format!("{}min", s / 60)
            }
        }
    }
}

/// Decompose seconds into the natural (value, unit) pair for form fields.
///
/// Returns `(value, "hours")` when the duration divides evenly into hours,
/// otherwise `(value, "minutes")`.
pub fn duration_to_value_unit(secs: Option<i32>) -> (Option<i32>, &'static str) {
    match secs {
        None => (None, "hours"),
        Some(s) if s >= 3600 && s % 3600 == 0 => (Some(s / 3600), "hours"),
        Some(s) => (Some(s / 60), "minutes"),
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

    // ==================== resolve_duration_seconds Tests ====================

    #[test]
    fn test_resolve_duration_none_value_returns_none() {
        assert_eq!(resolve_duration_seconds(None, None), Ok(None));
        assert_eq!(resolve_duration_seconds(None, Some("hours")), Ok(None));
    }

    #[test]
    fn test_resolve_duration_hours() {
        assert_eq!(
            resolve_duration_seconds(Some(2), Some("hours")),
            Ok(Some(7200))
        );
        assert_eq!(
            resolve_duration_seconds(Some(1), Some("hours")),
            Ok(Some(3600))
        );
        assert_eq!(
            resolve_duration_seconds(Some(24), Some("hours")),
            Ok(Some(86400))
        );
    }

    #[test]
    fn test_resolve_duration_minutes() {
        assert_eq!(
            resolve_duration_seconds(Some(30), Some("minutes")),
            Ok(Some(1800))
        );
        assert_eq!(
            resolve_duration_seconds(Some(1), Some("minutes")),
            Ok(Some(60))
        );
    }

    #[test]
    fn test_resolve_duration_defaults_to_minutes() {
        assert_eq!(resolve_duration_seconds(Some(30), None), Ok(Some(1800)));
    }

    #[test]
    fn test_resolve_duration_zero_value_error() {
        assert!(resolve_duration_seconds(Some(0), Some("hours")).is_err());
    }

    #[test]
    fn test_resolve_duration_negative_value_error() {
        assert!(resolve_duration_seconds(Some(-1), Some("hours")).is_err());
    }

    #[test]
    fn test_resolve_duration_exceeds_max_error() {
        assert!(resolve_duration_seconds(Some(25), Some("hours")).is_err());
        assert!(resolve_duration_seconds(Some(1441), Some("minutes")).is_err());
    }

    #[test]
    fn test_resolve_duration_invalid_unit_error() {
        assert!(resolve_duration_seconds(Some(2), Some("days")).is_err());
        assert!(resolve_duration_seconds(Some(2), Some("seconds")).is_err());
    }

    #[test]
    fn test_resolve_duration_overflow_error() {
        assert!(resolve_duration_seconds(Some(i32::MAX), Some("hours")).is_err());
    }

    // ==================== duration_display Tests ====================

    #[test]
    fn test_duration_display_none() {
        assert_eq!(duration_display(None), "Unlimited");
    }

    #[test]
    fn test_duration_display_exact_hours() {
        assert_eq!(duration_display(Some(3600)), "1h");
        assert_eq!(duration_display(Some(7200)), "2h");
        assert_eq!(duration_display(Some(28800)), "8h");
    }

    #[test]
    fn test_duration_display_minutes() {
        assert_eq!(duration_display(Some(1800)), "30min");
        assert_eq!(duration_display(Some(60)), "1min");
    }

    #[test]
    fn test_duration_display_mixed() {
        assert_eq!(duration_display(Some(5400)), "90min");
    }

    #[test]
    fn test_duration_display_zero() {
        assert_eq!(duration_display(Some(0)), "0min");
    }

    // ==================== duration_to_value_unit Tests ====================

    #[test]
    fn test_duration_to_value_unit_none() {
        assert_eq!(duration_to_value_unit(None), (None, "hours"));
    }

    #[test]
    fn test_duration_to_value_unit_exact_hours() {
        assert_eq!(duration_to_value_unit(Some(3600)), (Some(1), "hours"));
        assert_eq!(duration_to_value_unit(Some(7200)), (Some(2), "hours"));
    }

    #[test]
    fn test_duration_to_value_unit_minutes() {
        assert_eq!(duration_to_value_unit(Some(1800)), (Some(30), "minutes"));
        assert_eq!(duration_to_value_unit(Some(900)), (Some(15), "minutes"));
    }

    #[test]
    fn test_duration_to_value_unit_mixed() {
        assert_eq!(duration_to_value_unit(Some(5400)), (Some(90), "minutes"));
    }

    // ==================== Constants Tests ====================

    #[test]
    fn test_max_duration_is_24h() {
        assert_eq!(MAX_DURATION_SECONDS, 86_400);
    }

    #[test]
    fn test_default_duration_is_2h() {
        assert_eq!(DEFAULT_DURATION_SECONDS, 7_200);
    }
}
