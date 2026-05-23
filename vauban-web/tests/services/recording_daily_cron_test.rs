//! Recording daily cron configuration and scheduling tests.

use chrono::{TimeZone, Utc};
use chrono_tz::Tz;
use vauban_web::config::RecordingConfig;
use vauban_web::tasks::daily_cron::next_cron_instant;

#[test]
fn default_toml_pins_recording_daily_cron_knobs() {
    let default_toml = include_str!("../../../config/default.toml");
    assert!(
        default_toml.contains("recording_daily_cron_timezone"),
        "default.toml must document recording_daily_cron_timezone"
    );
    assert!(
        default_toml.contains("hydration_daily_cron_hour"),
        "default.toml must document hydration_daily_cron_hour"
    );
    assert!(
        default_toml.contains("retention_daily_cron_hour"),
        "default.toml must document retention_daily_cron_hour"
    );
    assert!(
        !default_toml.contains("hydration_daily_cron_hour_utc"),
        "legacy hydration_daily_cron_hour_utc must not remain in default.toml"
    );
    assert!(
        !default_toml.contains("retention_daily_cron_hour_utc"),
        "legacy retention_daily_cron_hour_utc must not remain in default.toml"
    );
}

#[test]
fn hydrator_and_reaper_tasks_use_daily_cron_helper() {
    let hydrator = include_str!("../../src/tasks/recording_hydrator.rs");
    let reaper = include_str!("../../src/tasks/recording_reaper.rs");
    for (name, src) in [("hydrator", hydrator), ("reaper", reaper)] {
        assert!(
            src.contains("daily_cron::next_cron_instant"),
            "{name} must schedule via daily_cron::next_cron_instant"
        );
        assert!(
            !src.contains("next_cron_instant_utc"),
            "{name} must not keep legacy UTC-only scheduler"
        );
    }
}

#[test]
fn recording_config_default_timezone_is_brussels() {
    let cfg = RecordingConfig::default();
    assert_eq!(cfg.recording_daily_cron_timezone, "Europe/Brussels");
    assert_eq!(cfg.daily_cron_timezone().unwrap(), Tz::Europe__Brussels);
}

#[test]
fn recording_config_validate_enforces_retention_after_hydration() {
    let cfg = RecordingConfig {
        hydration_daily_cron_hour: 6,
        retention_daily_cron_hour: 6,
        ..RecordingConfig::default()
    };
    assert!(cfg.validate().is_err());
}

#[test]
fn utc_timezone_preserves_legacy_utc_semantics() {
    let now = Utc.with_ymd_and_hms(2026, 4, 30, 10, 0, 0).unwrap();
    let d = next_cron_instant(now, Tz::UTC, 4);
    assert_eq!(d.as_secs(), 18 * 3600);
}

#[test]
fn brussels_midnight_crossing_to_hydrator_hour() {
    let now = Utc.with_ymd_and_hms(2026, 5, 21, 22, 0, 0).unwrap();
    let d = next_cron_instant(now, Tz::Europe__Brussels, 4);
    assert_eq!(d.as_secs(), 4 * 3600);
}
