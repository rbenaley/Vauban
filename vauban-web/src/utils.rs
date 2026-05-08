//! VAUBAN Web - Utility functions.
//!
//! Common utilities shared across the application.

use chrono::{DateTime, Utc};
use chrono_tz::Tz;

// ============================================================================
// Browser timezone formatting
// ============================================================================
//
// The web UI renders every operator-facing date/time in the browser
// timezone resolved from the `vbn_tz` cookie (see
// `crate::middleware::browser_tz`). The DB / IPC / logs / audit
// surfaces stay UTC; only the rendered HTML changes.
//
// Two formats live side by side:
//
// - `format_local`        -> "2026-05-08 22:14 CEST" (minute precision,
//                             list views, lozenges).
// - `format_local_with_seconds` -> "2026-05-08 22:14:33 CEST"
//                             (detail views, audit timelines, session
//                             connect/disconnect logs where second-level
//                             precision matters).
//
// Both are exposed to Askama templates via the `local` /
// `local_seconds` filters defined right below the helpers.
//
// `%Z` is chrono_tz's abbreviation: it returns `CEST` / `EST` /
// `IST` / `+0530` for half-hour offsets that have no human name.
// The fallback to a numeric offset is acceptable for every IANA
// identifier and keeps the format width-bounded.

/// Format a `DateTime<Utc>` in the browser timezone with minute
/// precision: `"2026-05-08 22:14 CEST"`.
///
/// The `tz` argument is sourced from
/// [`crate::middleware::BrowserTz`]; the caller has already validated
/// it. `Tz::UTC` yields `"2026-05-08 22:14 UTC"` -- the canonical
/// "no cookie posted yet" rendering.
pub fn format_local(dt: DateTime<Utc>, tz: Tz) -> String {
    dt.with_timezone(&tz).format("%Y-%m-%d %H:%M %Z").to_string()
}

/// Same shape as [`format_local`] with second precision:
/// `"2026-05-08 22:14:33 CEST"`. Used on detail pages and audit
/// timelines where second-level resolution matters.
pub fn format_local_with_seconds(dt: DateTime<Utc>, tz: Tz) -> String {
    dt.with_timezone(&tz)
        .format("%Y-%m-%d %H:%M:%S %Z")
        .to_string()
}

/// Convenience wrapper for `Option<DateTime<Utc>>`. Returns the
/// `none` literal as-is if the timestamp is absent. Used by handlers
/// that historically pre-formatted optional dates as `String` --
/// see `services::audit_authors` and `handlers::web::sessions`.
pub fn format_local_opt(dt: Option<DateTime<Utc>>, tz: Tz, none: &str) -> String {
    match dt {
        Some(d) => format_local(d, tz),
        None => none.to_string(),
    }
}

/// Same shape as [`format_local_opt`] with seconds.
pub fn format_local_with_seconds_opt(dt: Option<DateTime<Utc>>, tz: Tz, none: &str) -> String {
    match dt {
        Some(d) => format_local_with_seconds(d, tz),
        None => none.to_string(),
    }
}

// ----------------------------------------------------------------------------
// Askama filters
//
// Askama 0.15 picks up filters from a `pub mod filters {}` declared
// at the top level of any module visible to the template
// (`use askama::Template;` is enough). We declare ours next to the
// helpers so the wire (helper) and the template-facing surface
// (filter) cannot drift.
// ----------------------------------------------------------------------------

/// Custom Askama filters. Templates call them as `{{ dt|local(tz) }}`
/// and `{{ dt|local_seconds(tz) }}`.
///
/// Askama 0.15 requires custom filter functions to be marked with
/// `#[askama::filter_fn]` and to take `&dyn askama::Values` as their
/// second argument (the rendering environment). All extra args
/// (the `Tz`, the `none` placeholder) follow.
pub mod filters {
    use super::*;
    use askama::Values;

    /// `{{ dt|local(tz) }}` -> `"2026-05-08 22:14 CEST"`.
    ///
    /// `Tz` is passed by value (it implements `Copy`), so the
    /// invocation site reads `{{ rule.created_at|local(tz) }}`
    /// where `tz` is the template field of type [`Tz`] propagated
    /// from the handler.
    #[askama::filter_fn]
    pub fn local(dt: &DateTime<Utc>, _: &dyn Values, tz: &Tz) -> askama::Result<String> {
        Ok(format_local(*dt, *tz))
    }

    /// `{{ dt|local_seconds(tz) }}` -> `"2026-05-08 22:14:33 CEST"`.
    #[askama::filter_fn]
    pub fn local_seconds(dt: &DateTime<Utc>, _: &dyn Values, tz: &Tz) -> askama::Result<String> {
        Ok(format_local_with_seconds(*dt, *tz))
    }

    /// `{{ dt|local_opt(tz, "—") }}` -> `"2026-05-08 22:14 CEST"`
    /// or the literal placeholder when `dt` is `None`.
    #[askama::filter_fn]
    pub fn local_opt(
        dt: &Option<DateTime<Utc>>,
        _: &dyn Values,
        tz: &Tz,
        none: &str,
    ) -> askama::Result<String> {
        Ok(format_local_opt(*dt, *tz, none))
    }

    /// `{{ dt|local_seconds_opt(tz, "—") }}`.
    #[askama::filter_fn]
    pub fn local_seconds_opt(
        dt: &Option<DateTime<Utc>>,
        _: &dyn Values,
        tz: &Tz,
        none: &str,
    ) -> askama::Result<String> {
        Ok(format_local_with_seconds_opt(*dt, *tz, none))
    }
}

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
    use chrono::TimeZone;

    // ==================== Browser timezone formatting Tests ====================
    //
    // The chrono_tz database is embedded so the tests work
    // identically on every host (the CI box may itself run UTC).

    fn dt(year: i32, m: u32, d: u32, h: u32, mi: u32, s: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(year, m, d, h, mi, s).unwrap()
    }

    #[test]
    fn format_local_paris_summer_yields_cest() {
        // 2026-07-15 12:00 UTC = 14:00 in Paris (CEST = UTC+2).
        let out = format_local(dt(2026, 7, 15, 12, 0, 0), Tz::Europe__Paris);
        assert_eq!(out, "2026-07-15 14:00 CEST");
    }

    #[test]
    fn format_local_paris_winter_yields_cet() {
        // 2026-01-15 12:00 UTC = 13:00 in Paris (CET = UTC+1).
        let out = format_local(dt(2026, 1, 15, 12, 0, 0), Tz::Europe__Paris);
        assert_eq!(out, "2026-01-15 13:00 CET");
    }

    #[test]
    fn format_local_new_york_summer_yields_edt() {
        // 2026-07-15 12:00 UTC = 08:00 EDT (UTC-4).
        let out = format_local(dt(2026, 7, 15, 12, 0, 0), Tz::America__New_York);
        assert_eq!(out, "2026-07-15 08:00 EDT");
    }

    #[test]
    fn format_local_new_york_winter_yields_est() {
        // 2026-01-15 12:00 UTC = 07:00 EST (UTC-5).
        let out = format_local(dt(2026, 1, 15, 12, 0, 0), Tz::America__New_York);
        assert_eq!(out, "2026-01-15 07:00 EST");
    }

    #[test]
    fn format_local_calcutta_half_hour_offset() {
        // Asia/Calcutta = UTC+5:30 year-round.
        // 12:00 UTC -> 17:30 IST.
        let out = format_local(dt(2026, 6, 1, 12, 0, 0), Tz::Asia__Calcutta);
        assert_eq!(out, "2026-06-01 17:30 IST");
    }

    #[test]
    fn format_local_kathmandu_quarter_hour_offset() {
        // Asia/Kathmandu = UTC+5:45.
        let out = format_local(dt(2026, 6, 1, 12, 0, 0), Tz::Asia__Kathmandu);
        // chrono_tz emits the abbreviation `+0545` for fixed-offset
        // names that have no IATA shortcode.
        assert!(
            out.starts_with("2026-06-01 17:45 "),
            "kathmandu offset reflects in HH:MM, got `{}`",
            out
        );
    }

    #[test]
    fn format_local_utc_keeps_z_zone_label() {
        let out = format_local(dt(2026, 5, 8, 22, 14, 0), Tz::UTC);
        assert_eq!(out, "2026-05-08 22:14 UTC");
    }

    #[test]
    fn format_local_with_seconds_paris_summer() {
        let out = format_local_with_seconds(dt(2026, 7, 15, 12, 0, 33), Tz::Europe__Paris);
        assert_eq!(out, "2026-07-15 14:00:33 CEST");
    }

    #[test]
    fn format_local_with_seconds_utc() {
        let out = format_local_with_seconds(dt(2026, 5, 8, 22, 14, 5), Tz::UTC);
        assert_eq!(out, "2026-05-08 22:14:05 UTC");
    }

    /// DST spring-forward: 2026-03-29 02:30 Paris does not exist
    /// (clock jumps to 03:00). The closest UTC instant emits 03:30.
    #[test]
    fn format_local_handles_dst_spring_forward_paris() {
        // 02:30 UTC on 2026-03-29 = 04:30 CEST (already on summer
        // time -- DST kicked in at 01:00 UTC).
        let out = format_local(dt(2026, 3, 29, 2, 30, 0), Tz::Europe__Paris);
        assert_eq!(out, "2026-03-29 04:30 CEST");
    }

    /// DST fall-back: 2026-10-25 01:30 UTC = 02:30 CEST -> 02:30 CET
    /// at 01:00 UTC the clock falls back. Both sides are well-defined
    /// when expressed from UTC.
    #[test]
    fn format_local_handles_dst_fall_back_paris() {
        // 00:30 UTC = 02:30 CEST (still summer time).
        let out_pre = format_local(dt(2026, 10, 25, 0, 30, 0), Tz::Europe__Paris);
        assert_eq!(out_pre, "2026-10-25 02:30 CEST");
        // 01:30 UTC = 02:30 CET (after fall-back).
        let out_post = format_local(dt(2026, 10, 25, 1, 30, 0), Tz::Europe__Paris);
        assert_eq!(out_post, "2026-10-25 02:30 CET");
    }

    #[test]
    fn format_local_opt_present_yields_local() {
        let some = Some(dt(2026, 7, 15, 12, 0, 0));
        assert_eq!(
            format_local_opt(some, Tz::Europe__Paris, "—"),
            "2026-07-15 14:00 CEST"
        );
    }

    #[test]
    fn format_local_opt_none_yields_placeholder() {
        assert_eq!(format_local_opt(None, Tz::Europe__Paris, "—"), "—");
        assert_eq!(format_local_opt(None, Tz::UTC, "(none)"), "(none)");
    }

    #[test]
    fn format_local_with_seconds_opt_present_and_absent() {
        let some = Some(dt(2026, 7, 15, 12, 0, 33));
        assert_eq!(
            format_local_with_seconds_opt(some, Tz::Europe__Paris, "—"),
            "2026-07-15 14:00:33 CEST"
        );
        assert_eq!(
            format_local_with_seconds_opt(None, Tz::Europe__Paris, "—"),
            "—"
        );
    }

    /// Round-trip: format-then-parse keeps the wall-clock minute even
    /// across edge timezones. We don't try to parse `%Z` back (it is
    /// inherently lossy for half-hour zones) -- we only check the
    /// numeric prefix is unambiguous.
    #[test]
    fn format_local_numeric_prefix_is_unambiguous_per_tz() {
        let when = dt(2026, 5, 8, 22, 14, 0);
        for tz in [
            Tz::UTC,
            Tz::Europe__Paris,
            Tz::Europe__London,
            Tz::America__New_York,
            Tz::America__Los_Angeles,
            Tz::Asia__Calcutta,
            Tz::Asia__Tokyo,
            Tz::Australia__Sydney,
        ] {
            let out = format_local(when, tz);
            assert!(
                out.len() >= 16,
                "format must emit at least YYYY-MM-DD HH:MM (16 chars) -- got `{}`",
                out
            );
            let prefix = &out[..16]; // YYYY-MM-DD HH:MM
            assert_eq!(prefix.as_bytes()[10], b' ');
            assert_eq!(prefix.as_bytes()[13], b':');
        }
    }

    /// End-to-end via Askama: a tiny fixture template renders the
    /// `local` filter so a future drift in askama 0.15's filter
    /// signature is caught at the unit-test level.
    #[test]
    fn local_filter_renders_in_askama_template() {
        use askama::Template;
        #[derive(Template)]
        #[template(
            ext = "txt",
            source = "{{ when|local(tz) }} | {{ when|local_seconds(tz) }} | {{ maybe|local_opt(tz, \"-\") }} | {{ maybe|local_seconds_opt(tz, \"-\") }}"
        )]
        struct Fixture {
            when: DateTime<Utc>,
            tz: Tz,
            maybe: Option<DateTime<Utc>>,
        }
        let when = dt(2026, 7, 15, 12, 0, 33);
        let tpl = Fixture {
            when,
            tz: Tz::Europe__Paris,
            maybe: Some(when),
        };
        let out = tpl.render().expect("render");
        assert_eq!(
            out,
            "2026-07-15 14:00 CEST | 2026-07-15 14:00:33 CEST | 2026-07-15 14:00 CEST | 2026-07-15 14:00:33 CEST"
        );

        let tpl_none = Fixture {
            when,
            tz: Tz::Europe__Paris,
            maybe: None,
        };
        let out = tpl_none.render().expect("render");
        assert_eq!(
            out,
            "2026-07-15 14:00 CEST | 2026-07-15 14:00:33 CEST | - | -"
        );
    }

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
