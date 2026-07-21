//! Pins and unit tests for IACS recording health telemetry (Lot F).

use std::sync::atomic::Ordering;
use vauban_web::services::system_health::{IacsRecordingTelemetry, SystemHealth};

const PROXY_IACS_RS: &str = include_str!("../../src/ipc/proxy_iacs.rs");
const SYSTEM_HEALTH_RS: &str = include_str!("../../src/services/system_health.rs");

#[test]
fn system_health_struct_carries_iacs_recording_fields() {
    for field in [
        "iacs_ack_timeouts: u64",
        "iacs_ack_dropped: u64",
        "iacs_ack_wait_ms_max: u64",
    ] {
        assert!(
            SYSTEM_HEALTH_RS.contains(field),
            "SystemHealth missing field {field}"
        );
    }
}

#[test]
fn system_health_cache_reads_iacs_recording_telemetry() {
    assert!(
        SYSTEM_HEALTH_RS.contains("iacs_recording"),
        "SystemHealthCache::compute must read iacs_recording telemetry"
    );
    assert!(
        SYSTEM_HEALTH_RS.contains("iacs_ack_timeouts"),
        "compute must populate iacs_ack_timeouts"
    );
}

#[test]
fn proxy_iacs_handles_iacs_proxy_health_message() {
    assert!(
        PROXY_IACS_RS.contains("Message::IacsProxyHealth"),
        "process_incoming must handle IacsProxyHealth"
    );
    assert!(
        PROXY_IACS_RS.contains("iacs_recording_telemetry"),
        "health handler must update AppState telemetry"
    );
}

#[test]
fn proxy_iacs_coalesces_ack_timeout_notifications() {
    assert!(
        PROXY_IACS_RS.contains("iacs_recording_ack_timeout"),
        "notification payload must use iacs_recording_ack_timeout type"
    );
    assert!(
        PROXY_IACS_RS.contains("Duration::from_secs(60)"),
        "notifications must be coalesced to at most one per minute"
    );
    assert!(
        PROXY_IACS_RS.contains("WsChannel::Notifications"),
        "ack-timeout alerts must fan out on Notifications channel"
    );
}

#[test]
fn iacs_proxy_health_updates_app_state_atomics() {
    let tel = IacsRecordingTelemetry::default();
    tel.ack_timeouts.store(3, Ordering::SeqCst);
    tel.ack_dropped.store(1, Ordering::SeqCst);
    tel.ack_wait_ms_max.store(2500, Ordering::SeqCst);

    assert_eq!(tel.ack_timeouts.load(Ordering::SeqCst), 3);
    assert_eq!(tel.ack_dropped.load(Ordering::SeqCst), 1);
    assert_eq!(tel.ack_wait_ms_max.load(Ordering::SeqCst), 2500);
}

#[test]
fn system_health_degraded_zeros_iacs_recording_fields() {
    use vauban_web::services::broker_latency::LatencySnapshot;
    use vauban_web::services::system_health::PoolHealth;

    let h = SystemHealth::degraded(
        LatencySnapshot {
            count: 0,
            median_us: None,
            p95_us: None,
            window_secs: 300,
        },
        PoolHealth {
            max_size: 8,
            size: 1,
            available: 1,
            waiting: 0,
        },
    );
    assert_eq!(h.iacs_ack_timeouts, 0);
    assert_eq!(h.iacs_ack_dropped, 0);
    assert_eq!(h.iacs_ack_wait_ms_max, 0);
}
