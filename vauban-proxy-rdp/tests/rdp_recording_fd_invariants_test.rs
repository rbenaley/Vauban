//! Source invariants for proxy-owned RDP recording FDs.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repository root")
        .to_path_buf()
}

#[test]
fn rdp_recording_fd_lint_passes() {
    let script =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/check_rdp_recording_fd.sh");
    let output = Command::new("bash")
        .arg(&script)
        .output()
        .expect("run RDP recording lint");
    assert!(
        output.status.success(),
        "lint failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn rdp_recording_end_wire_carries_segment_seal_stats() {
    let messages = std::fs::read_to_string(repo_root().join("shared/src/messages.rs")).unwrap();
    let struct_start = messages
        .find("pub struct RdpRecordingSegment")
        .expect("RdpRecordingSegment");
    let segment = &messages[struct_start..struct_start + 500];
    for field in [
        "index",
        "width",
        "height",
        "duration_ticks",
        "init_size",
        "file_size",
        "blake3_hex",
        "codec_string",
    ] {
        assert!(segment.contains(field), "segment wire missing {field}");
    }
    let end_start = messages.find("RdpRecordingEnd {").expect("RdpRecordingEnd");
    let end = &messages[end_start..end_start + 350];
    for field in [
        "segments",
        "meta_json_relative_path",
        "total_frames",
        "total_bytes",
    ] {
        assert!(end.contains(field), "RdpRecordingEnd missing {field}");
    }
}

#[test]
fn recording_path_never_sends_video_frames_to_audit() {
    let session = include_str!("../src/session.rs");
    assert!(!session.contains("let audit_msg = Message::RdpVideoFrame"));
    assert!(session.contains("writer.handle_frame("));
    assert!(session.contains("lease_recording_file("));
}

#[test]
fn main_loop_is_only_recording_fd_receiver() {
    let main = include_str!("../src/main.rs");
    assert!(main.contains("Message::RecordingFileResponse"));
    assert!(main.contains("recv_fd_timed("));
    assert!(main.contains("pending_recording_leases"));
}
