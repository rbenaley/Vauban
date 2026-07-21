//! Cross-crate structural pins for the IACS recording pipeline.

#[test]
fn shared_messages_include_iacs_recording_variants() {
    let src = include_str!("../../shared/src/messages.rs");
    for variant in [
        "IacsRecordingSessionStart",
        "IacsRecordingChannelStart",
        "IacsRecordingData",
        "IacsRecordingDataAck",
        "IacsRecordingChannelEnd",
        "IacsRecordingSessionEnd",
        // Wire-compat stubs (mid-enum; must remain for bincode discriminants).
        "RecordingFileGzipRequest",
        "RecordingFileGzipResponse",
        // Lot C: unlink broker replaces root-side gzip.
        "RecordingFileUnlinkRequest",
        "RecordingFileUnlinkResponse",
    ] {
        assert!(src.contains(variant), "missing message variant {variant}");
    }
}

#[test]
fn supervisor_handles_unlink_request() {
    let src = include_str!("../src/main.rs");
    assert!(src.contains("fn handle_recording_file_unlink_request"));
    assert!(src.contains("RecordingFileUnlinkRequest"));
    assert!(src.contains("validate_recording_unlink_relative_path"));
}

#[test]
fn supervisor_src_has_no_flate2_or_gzencoder() {
    let src = include_str!("../src/main.rs");
    assert!(
        !src.contains("GzEncoder"),
        "supervisor must not gzip IACS PCAPs (CPU work moved to audit)"
    );
    assert!(
        !src.contains("use flate2"),
        "supervisor must not import flate2"
    );
    assert!(
        !include_str!("../Cargo.toml").contains("flate2"),
        "vauban-supervisor/Cargo.toml must not depend on flate2"
    );
}

#[test]
fn supervisor_gzip_stub_never_succeeds() {
    // Gzip variants stay mid-enum for wire compat but the handler is a
    // fail-closed stub — no success path may remain.
    let src = include_str!("../src/main.rs");
    assert!(src.contains("fn handle_recording_file_gzip_request"));
    assert!(src.contains("deprecated: gzip moved to vauban-audit"));
    assert!(
        !src.contains("blake3_hex: Some("),
        "deprecated gzip stub must not return a blake3 success payload"
    );
}

#[test]
fn audit_gzips_iacs_pcap_on_channel_end() {
    let mgr = include_str!("../../vauban-audit/src/iacs_recording_manager.rs");
    assert!(mgr.contains("fn gzip_channel_pcap_on_fds"));
    assert!(mgr.contains("GzEncoder"));
    let main = include_str!("../../vauban-audit/src/main.rs");
    assert!(main.contains("gzip_channel_and_unlink"));
    assert!(main.contains("request_unlink_from_supervisor"));
    assert!(!main.contains("request_gzip_from_supervisor"));
}

#[test]
fn audit_iacs_manager_module_exists() {
    let src = include_str!("../../vauban-audit/src/iacs_recording_manager.rs");
    assert!(src.contains("pcap-bundle"));
    assert!(src.contains("sync_data"));
}

#[test]
fn web_hydrator_supports_pcap_bundle() {
    let src = include_str!("../../vauban-web/src/services/recording_hydrator.rs");
    assert!(src.contains("FORMAT_PCAP_BUNDLE"));
}

#[test]
fn web_download_supports_iacs_zip() {
    let src = include_str!("../../vauban-web/src/handlers/web/sessions.rs");
    assert!(src.contains("stream_iacs_pcap_zip"));
}

#[test]
fn config_exposes_recording_iacs_flag() {
    let src = include_str!("../src/config.rs");
    assert!(src.contains("pub iacs: bool"));
}
