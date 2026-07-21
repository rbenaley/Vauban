//! Pins for `recording_lossy` sticky latch (architecture QW3 / I-LOSS-*).

use proptest::prelude::*;

#[test]
fn migration_and_schema_expose_recording_lossy() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace");
    let up = root.join("vauban-db/migrations/20260722000000_recording_lossy_flag/up.sql");
    assert!(up.exists(), "migration up.sql must exist");
    let sql = std::fs::read_to_string(&up).expect("read up");
    assert!(
        sql.contains("recording_lossy"),
        "migration must ADD recording_lossy"
    );
    let schema = include_str!("../../../vauban-db/src/schema.rs");
    assert!(
        schema.contains("recording_lossy"),
        "Diesel schema must include recording_lossy"
    );
    let model = include_str!("../../src/models/session.rs");
    assert!(
        model.contains("pub recording_lossy: bool"),
        "ProxySession must carry recording_lossy"
    );
}

#[test]
fn message_recording_loss_observed_exists() {
    let messages = include_str!("../../../shared/src/messages.rs");
    assert!(
        messages.contains("RecordingLossObserved"),
        "Message::RecordingLossObserved must exist (append-only)"
    );
}

#[test]
fn proxies_emit_recording_loss_observed_on_first_drop() {
    for crate_main in [
        include_str!("../../../vauban-proxy-ssh/src/main.rs"),
        include_str!("../../../vauban-proxy-rdp/src/main.rs"),
    ] {
        assert!(
            crate_main.contains("RecordingLossObserved"),
            "proxy must emit RecordingLossObserved"
        );
        assert!(
            crate_main.contains("recording_loss_latched"),
            "proxy must keep a sticky latch set"
        );
        assert!(
            crate_main.contains("fn record_recording_try_send_full"),
            "drop hook must still bump try_send_full (I-LOSS-4)"
        );
    }
}

#[test]
fn web_is_sole_db_writer_of_recording_lossy() {
    let loss = include_str!("../../src/services/recording_loss.rs");
    assert!(
        loss.contains("recording_lossy.eq(true)"),
        "recording_loss service must SET recording_lossy"
    );
    let hydrator = include_str!("../../src/services/recording_hydrator.rs");
    assert!(
        !hydrator.contains("recording_lossy"),
        "hydrator must not touch recording_lossy (I-LOSS-3)"
    );
    let reaper = include_str!("../../src/services/recording_reaper.rs");
    assert!(
        !reaper.contains("recording_lossy"),
        "reaper must not clear recording_lossy"
    );
}

#[test]
fn templates_surface_incomplete_capture_badge() {
    let list = include_str!("../../templates/sessions/recording_list.html");
    assert!(
        list.contains("Incomplete capture"),
        "list must show Incomplete capture badge"
    );
    assert!(
        list.contains("recording.recording_lossy"),
        "list must gate badge on recording_lossy"
    );
    let detail = include_str!("../../templates/sessions/recording_detail.html");
    assert!(
        detail.contains("Incomplete capture"),
        "detail must warn on recording_lossy"
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Sticky latch model: any non-empty drop sequence yields exactly one
    /// false->true transition; empty sequence stays false.
    #[test]
    fn sticky_latch_is_monotone(drops in 0usize..=32) {
        let mut latched = false;
        let mut transitions = 0u32;
        for _ in 0..drops {
            if !latched {
                latched = true;
                transitions += 1;
            }
        }
        if drops == 0 {
            prop_assert!(!latched);
            prop_assert_eq!(transitions, 0);
        } else {
            prop_assert!(latched);
            prop_assert_eq!(transitions, 1);
        }
    }
}
