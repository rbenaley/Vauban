//! Wall-clock daily cron scheduling for recording background tasks.
//!
//! Anchors SAFETY-net crons at `hour:00` in an explicit IANA timezone
//! (`[recording].recording_daily_cron_timezone`), not the server OS TZ
//! and not UTC unless configured as `"UTC"`.

use std::time::Duration;

use chrono::{DateTime, Datelike, TimeZone, Utc};
use chrono_tz::Tz;

/// Compute the duration between `now_utc` and the next `hour:00:00` in
/// `tz`. Used to align hydrator / reaper daily crons with a stable
/// operator-chosen wall-clock anchor.
///
/// If `now` is exactly at the target instant, the next firing is one
/// calendar day later (avoids double-fire when boot aligns with cron).
pub fn next_cron_instant(now_utc: DateTime<Utc>, tz: Tz, hour: u8) -> Duration {
    let now_local = now_utc.with_timezone(&tz);
    let Some(target_today) = tz
        .with_ymd_and_hms(
            now_local.year(),
            now_local.month(),
            now_local.day(),
            u32::from(hour),
            0,
            0,
        )
        .single()
    else {
        // Ambiguous / non-existent local time (DST edge). Defensive
        // fallback: retry in 24 h; boot-time validate rejects bad configs.
        return Duration::from_secs(24 * 3600);
    };

    let target_local = if target_today > now_local {
        target_today
    } else {
        let tomorrow = now_local.date_naive() + chrono::Days::new(1);
        match tomorrow.and_hms_opt(u32::from(hour), 0, 0) {
            Some(naive) => match tz.from_local_datetime(&naive).single() {
                Some(t) => t,
                None => target_today + chrono::Duration::days(1),
            },
            None => return Duration::from_secs(24 * 3600),
        }
    };

    let delta = target_local.with_timezone(&Utc) - now_utc;
    Duration::from_secs(delta.num_seconds().max(0) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_now_before_target_same_day() {
        let now = Utc.with_ymd_and_hms(2026, 4, 30, 2, 0, 0).unwrap();
        let d = next_cron_instant(now, Tz::UTC, 4);
        assert_eq!(d.as_secs(), 2 * 3600);
    }

    #[test]
    fn utc_now_after_target_wraps_to_next_day() {
        let now = Utc.with_ymd_and_hms(2026, 4, 30, 10, 0, 0).unwrap();
        let d = next_cron_instant(now, Tz::UTC, 4);
        assert_eq!(d.as_secs(), 18 * 3600);
    }

    #[test]
    fn utc_exactly_at_target_wraps() {
        let now = Utc.with_ymd_and_hms(2026, 4, 30, 4, 0, 0).unwrap();
        let d = next_cron_instant(now, Tz::UTC, 4);
        assert_eq!(d.as_secs(), 24 * 3600);
    }

    #[test]
    fn brussels_now_before_target_same_day() {
        // 2026-05-22 02:00 CEST (UTC+2) -> next 04:00 Brussels = +2h
        let now = Utc.with_ymd_and_hms(2026, 5, 22, 0, 0, 0).unwrap();
        let d = next_cron_instant(now, Tz::Europe__Brussels, 4);
        assert_eq!(d.as_secs(), 2 * 3600);
    }

    #[test]
    fn brussels_now_after_target_wraps() {
        // 2026-05-22 06:00 CEST = 04:00 UTC -> next 04:00 Brussels is May 23 02:00 UTC
        let now = Utc.with_ymd_and_hms(2026, 5, 22, 4, 0, 0).unwrap();
        let d = next_cron_instant(now, Tz::Europe__Brussels, 4);
        assert_eq!(d.as_secs(), 22 * 3600);
    }

    #[test]
    fn brussels_retention_one_hour_after_hydration_default() {
        let tz = Tz::Europe__Brussels;
        let now = Utc.with_ymd_and_hms(2026, 5, 22, 0, 30, 0).unwrap();
        let hydrator = next_cron_instant(now, tz, 4);
        let reaper = next_cron_instant(now, tz, 5);
        assert_eq!(hydrator.as_secs(), 90 * 60);
        assert_eq!(reaper.as_secs(), 150 * 60);
        assert!(
            reaper > hydrator,
            "default retention hour must fire after hydrator"
        );
    }

    #[test]
    fn dst_spring_forward_brussels_hour_four_exists() {
        // EU spring forward 2026-03-29: 02:00 -> 03:00. Hour 4 exists.
        let now = Utc.with_ymd_and_hms(2026, 3, 29, 0, 0, 0).unwrap();
        let d = next_cron_instant(now, Tz::Europe__Brussels, 4);
        assert_eq!(d.as_secs(), 2 * 3600);
    }
}
