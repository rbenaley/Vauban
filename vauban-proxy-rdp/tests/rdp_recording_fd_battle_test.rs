//! Adversarial source pins for the RDP segment lease lifecycle.

#![allow(clippy::expect_used)]

#[test]
fn every_resolution_split_finalizes_before_requesting_next_fd() {
    let writer = include_str!("../src/rdp_recording_writer.rs");
    let split = writer
        .find("if is_keyframe")
        .expect("resolution split branch");
    let branch = &writer[split..split + 1_200];
    let finalize = branch
        .find("self.finalize_segment()")
        .expect("finalize old segment");
    let pending = branch
        .find("self.pending_frame = Some")
        .expect("buffer split keyframe");
    assert!(finalize < pending);
    assert!(branch.contains("{:03}.mp4"));
}

#[test]
fn lease_failures_are_bounded_and_observable() {
    let session = include_str!("../src/session.rs");
    assert!(session.contains("DEFAULT_BROKER_TIMEOUT"));
    assert!(session.contains("RecordingLossObserved"));
    assert!(session.contains("recording_writer = None"));
}

#[test]
fn audit_is_metadata_only_for_rdp_media() {
    let audit = include_str!("../../vauban-audit/src/main.rs");
    let handler = audit
        .find("fn handle_recording_message")
        .expect("RDP recording handler");
    let source = &audit[handler..handler + 6_000];
    assert!(source.contains("Ignoring legacy RdpVideoFrame"));
    assert!(source.contains("RDP proxy owns media files"));
    assert!(!source.contains("mgr.handle_frame"));
    assert!(!source.contains("mgr.start_session"));
}
