//! Battle pins: SSH recording must survive bursty output without IPC try_send.

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[test]
fn battle_session_manager_has_no_audit_data_firehose() {
    let src = include_str!("../src/session_manager.rs");
    assert!(!src.contains("SshRecordingData"));
    assert!(!src.contains("try_send_recording"));
    assert!(src.contains("observe_recording_error"));
    assert!(src.contains("RecordingLossObserved"));
    assert!(
        src.contains("sync_if_dirty") || src.contains("interval"),
        "session task must periodically fsync dirty cast"
    );
}

#[test]
fn battle_main_demuxes_recording_file_response() {
    let main = include_str!("../src/main.rs");
    assert!(main.contains("RecordingFileResponse"));
    assert!(main.contains("RecordingFileRequest"));
    assert!(main.contains("recv_fd_timed"));
    assert!(
        main.contains("pending_recording_leases")
            || main.contains("recording_lease")
            || main.contains("RecordingLease"),
        "main loop must track pending recording leases"
    );
}

#[test]
fn battle_audit_ignores_legacy_ssh_recording_data() {
    let audit = include_str!("../../vauban-audit/src/main.rs");
    let start = audit
        .find("Message::SshRecordingData")
        .expect("SshRecordingData arm");
    let window = &audit[start..start.saturating_add(500).min(audit.len())];
    assert!(
        window.contains("ignoring")
            || window.contains("legacy")
            || window.contains("proxy-owned")
            || window.contains("warn!"),
        "audit must not write media on SshRecordingData"
    );
    assert!(
        !window.contains("handle_data("),
        "audit must not call handle_data for SshRecordingData"
    );
}
