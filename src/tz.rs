//! Browser timezone cookie (`vcp_tz`) and server-side local formatting.

use chrono::{DateTime, TimeZone, Utc};
use chrono_tz::Tz;
use topcoat::{
    context::Cx,
    cookie::{Cookies, cookies},
};

/// Cookie name carrying the visitor IANA timezone (e.g. `Europe/Paris`).
pub const VCP_TZ_COOKIE: &str = "vcp_tz";

/// Resolve the request timezone from `vcp_tz`, defaulting to UTC.
pub fn browser_tz(cx: &Cx) -> Tz {
    let jar = cookies(cx);
    jar.get(VCP_TZ_COOKIE)
        .and_then(|c| c.value().parse::<Tz>().ok())
        .unwrap_or(Tz::UTC)
}

/// Minute precision: `YYYY-MM-DD HH:MM ZZZ`.
pub fn format_local(dt: DateTime<Utc>, tz: Tz) -> String {
    dt.with_timezone(&tz)
        .format("%Y-%m-%d %H:%M %Z")
        .to_string()
}

/// Second precision: `YYYY-MM-DD HH:MM:SS ZZZ`.
pub fn format_local_with_seconds(dt: DateTime<Utc>, tz: Tz) -> String {
    dt.with_timezone(&tz)
        .format("%Y-%m-%d %H:%M:%S %Z")
        .to_string()
}

/// Format a unix-seconds instant in the visitor timezone.
pub fn format_unix_local(secs: i64, tz: Tz) -> String {
    match Utc.timestamp_opt(secs, 0).single() {
        Some(dt) => format_local(dt, tz),
        None => format!("{secs}"),
    }
}

/// RFC 3339 UTC for `<time datetime>`.
pub fn unix_rfc3339(secs: i64) -> String {
    match Utc.timestamp_opt(secs, 0).single() {
        Some(dt) => dt.to_rfc3339(),
        None => String::new(),
    }
}

/// Compact relative label for activity feeds (`3h ago`, `2d ago`).
/// Falls back to `YYYY-MM-DD` in `tz` when older than a week.
pub fn format_relative(secs: i64, now: i64, tz: Tz) -> String {
    let delta = now.saturating_sub(secs);
    if delta < 60 {
        return "just now".to_owned();
    }
    if delta < 3_600 {
        return format!("{}m ago", delta / 60);
    }
    if delta < 86_400 {
        return format!("{}h ago", delta / 3_600);
    }
    if delta < 86_400 * 7 {
        return format!("{}d ago", delta / 86_400);
    }
    match Utc.timestamp_opt(secs, 0).single() {
        Some(dt) => dt.with_timezone(&tz).format("%Y-%m-%d").to_string(),
        None => format!("{secs}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_local_changes_with_tz() {
        let dt = Utc.with_ymd_and_hms(2026, 6, 23, 12, 0, 0).unwrap();
        let utc = format_local(dt, Tz::UTC);
        let paris = format_local(dt, Tz::Europe__Paris);
        assert!(utc.contains("12:00"));
        assert!(paris.contains("14:00") || paris.contains("13:00")); // DST-dependent
        assert_ne!(utc, paris);
    }

    #[test]
    fn cookie_name_is_stable() {
        assert_eq!(VCP_TZ_COOKIE, "vcp_tz");
    }

    #[test]
    fn format_relative_buckets() {
        let now = 1_000_000_i64;
        assert_eq!(format_relative(now - 30, now, Tz::UTC), "just now");
        assert_eq!(format_relative(now - 120, now, Tz::UTC), "2m ago");
        assert_eq!(format_relative(now - 7_200, now, Tz::UTC), "2h ago");
        assert_eq!(format_relative(now - 172_800, now, Tz::UTC), "2d ago");
        let week_plus = format_relative(now - 86_400 * 10, now, Tz::UTC);
        assert!(week_plus.contains('-'), "got {week_plus}");
    }
}
