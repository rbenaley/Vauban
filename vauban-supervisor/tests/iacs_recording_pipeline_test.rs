//! Cross-crate structural pins for the IACS recording pipeline.

#[test]
fn shared_messages_include_iacs_recording_variants() {
    let src = include_str!("../../shared/src/messages.rs");
    for variant in [
        "IacsRecordingChannelStart",
        "IacsRecordingData",
        "IacsRecordingDataAck",
        "IacsRecordingChannelEnd",
        "IacsRecordingSessionEnd",
        "RecordingFileGzipRequest",
        "RecordingFileGzipResponse",
    ] {
        assert!(src.contains(variant), "missing message variant {variant}");
    }
}

#[test]
fn supervisor_handles_gzip_request() {
    let src = include_str!("../src/main.rs");
    assert!(src.contains("fn handle_recording_file_gzip_request"));
    assert!(src.contains("RecordingFileGzipRequest"));
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
