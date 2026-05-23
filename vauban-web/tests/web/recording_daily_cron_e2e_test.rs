//! E2E pins for recording daily cron timezone configuration.

use vauban_web::config::RecordingConfig;

#[test]
fn main_wires_recording_daily_cron_timezone() {
    let main_rs = include_str!("../../src/main.rs");
    assert!(
        main_rs.contains("daily_cron_timezone()"),
        "main.rs must resolve recording_daily_cron_timezone for background tasks"
    );
    assert!(
        main_rs.contains("hydration_daily_cron_hour"),
        "main.rs must pass hydration_daily_cron_hour to the hydrator cron"
    );
    assert!(
        main_rs.contains("retention_daily_cron_hour"),
        "main.rs must pass retention_daily_cron_hour to the reaper cron"
    );
}

#[test]
fn vauban_conf_documents_iana_recording_cron_timezone() {
    let conf = include_str!("../../../config/vauban.conf");
    assert!(
        conf.contains("recording_daily_cron_timezone"),
        "vauban.conf must expose recording_daily_cron_timezone"
    );
    assert!(
        conf.contains("hydration_daily_cron_hour"),
        "vauban.conf must expose hydration_daily_cron_hour"
    );
    assert!(
        conf.contains("retention_daily_cron_hour"),
        "vauban.conf must expose retention_daily_cron_hour"
    );
}

#[test]
fn loaded_default_recording_config_validates() {
    let cfg = RecordingConfig::default();
    cfg.validate()
        .expect("default RecordingConfig must validate for E2E boot");
    assert!(
        cfg.retention_daily_cron_hour > cfg.hydration_daily_cron_hour,
        "default retention cron must fire after hydrator cron"
    );
}
