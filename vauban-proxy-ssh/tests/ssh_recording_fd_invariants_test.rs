//! Source invariants for proxy-owned SSH recording FDs.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace")
        .to_path_buf()
}

#[test]
fn check_ssh_recording_fd_lint_passes() {
    let script =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/check_ssh_recording_fd.sh");
    assert!(script.exists(), "missing {}", script.display());
    let out = Command::new("bash")
        .arg(&script)
        .output()
        .expect("run lint");
    assert!(
        out.status.success(),
        "check_ssh_recording_fd.sh failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn ssh_recording_end_wire_carries_seal_stats() {
    let messages = std::fs::read_to_string(repo_root().join("shared/src/messages.rs")).unwrap();
    let start = messages
        .find("SshRecordingEnd {")
        .expect("SshRecordingEnd variant");
    let window = &messages[start..start + 400];
    for field in [
        "blake3_hex",
        "total_bytes",
        "total_events",
        "duration_secs",
        "meta_json_relative_path",
    ] {
        assert!(window.contains(field), "SshRecordingEnd missing {field}");
    }
}

#[test]
fn proxy_does_not_emit_ssh_recording_data() {
    let session = include_str!("../src/session_manager.rs");
    assert!(!session.contains("SshRecordingData"));
    assert!(session.contains("SshRecordingEnd"));
    assert!(session.contains("SshCastWriter") || session.contains("ssh_cast_writer"));
}
