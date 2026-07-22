//! Source invariants for off-thread IACS ChannelEnd gzip.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::PathBuf;
use std::process::Command;

fn main_rs() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/main.rs");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn worker_rs() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/iacs_gzip_worker.rs");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn script_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("scripts")
        .join("check_iacs_gzip_offthread.sh")
}

#[test]
fn inv_handle_iacs_does_not_run_gzip_cpu() {
    let main = main_rs();
    let start = main
        .find("fn handle_iacs_recording_message")
        .expect("handle_iacs");
    let body = &main[start..start.saturating_add(7000).min(main.len())];
    assert!(
        !body.contains("gzip_channel_pcap_on_fds"),
        "handle_iacs must not call gzip_channel_pcap_on_fds"
    );
    assert!(
        !body.contains("GzEncoder"),
        "handle_iacs must not construct GzEncoder"
    );
    assert!(
        body.contains("enqueue_iacs_gzip_job"),
        "ChannelEnd must enqueue GzipCpuJob"
    );
}

#[test]
fn inv_main_drains_gzip_completions() {
    let main = main_rs();
    assert!(main.contains("fn drain_gzip_completions"));
    let loop_start = main.find("fn main_loop").expect("main_loop");
    let loop_body = &main[loop_start..loop_start.saturating_add(10_000).min(main.len())];
    assert!(
        loop_body.contains("drain_gzip_completions("),
        "main_loop must drain gzip completions"
    );
}

#[test]
fn inv_sync_gzip_helper_retired() {
    let main = main_rs();
    assert!(
        !main.contains("gzip_channel_and_unlink"),
        "sync gzip_channel_and_unlink must stay deleted"
    );
}

#[test]
fn inv_worker_is_cpu_only_no_ipc() {
    let worker = worker_rs();
    assert!(worker.contains("fn run_gzip_cpu"));
    assert!(worker.contains("fn spawn_gzip_worker"));
    assert!(worker.contains("gzip_channel_pcap_on_fds"));
    for forbidden in [
        "use shared::ipc",
        "IpcChannel::",
        "request_file_from_supervisor",
        "request_unlink_from_supervisor",
        "SUPERVISOR_BROKER",
    ] {
        assert!(
            !worker.contains(forbidden),
            "worker must not contain `{forbidden}`"
        );
    }
}

#[test]
fn inv_broker_still_used_for_dst_and_unlink_only() {
    let main = main_rs();
    let enqueue = main
        .find("fn enqueue_iacs_gzip_job")
        .expect("enqueue_iacs_gzip_job");
    let enqueue_body = &main[enqueue..enqueue.saturating_add(2500).min(main.len())];
    assert!(
        enqueue_body.contains("request_file_from_supervisor"),
        "enqueue must broker-open dst FD"
    );
    let drain = main
        .find("fn drain_gzip_completions")
        .expect("drain_gzip_completions");
    let drain_body = &main[drain..drain.saturating_add(2500).min(main.len())];
    assert!(
        drain_body.contains("request_unlink_from_supervisor"),
        "drain must unlink raw after successful CPU"
    );
    assert!(
        drain_body.contains("finalize_channel_gzip"),
        "drain must finalize on success"
    );
}

#[test]
fn inv_session_end_defers_on_pending_gzip() {
    let main = main_rs();
    let start = main
        .find("fn handle_iacs_recording_message")
        .expect("handle_iacs");
    let body = &main[start..start.saturating_add(7000).min(main.len())];
    assert!(body.contains("session_end_unblocked"));
    assert!(body.contains("deferred_session_ends"));
    assert!(body.contains("finish_iacs_session_end"));
}

#[test]
fn check_iacs_gzip_offthread_lint_passes() {
    let script = script_path();
    assert!(script.exists(), "missing {}", script.display());
    let out = Command::new("bash")
        .arg(&script)
        .output()
        .unwrap_or_else(|e| panic!("spawn {}: {e}", script.display()));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "check_iacs_gzip_offthread.sh failed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

#[test]
fn lint_script_executable_and_covers_needles() {
    use std::os::unix::fs::PermissionsExt;
    let path = script_path();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert!(mode & 0o111 != 0, "script not executable");
    let body = std::fs::read_to_string(&path).unwrap();
    for needle in [
        "gzip_channel_pcap_on_fds",
        "enqueue_iacs_gzip_job",
        "drain_gzip_completions",
        "IpcChannel::",
        "GzipCpuJob",
    ] {
        assert!(body.contains(needle), "lint must reference `{needle}`");
    }
}
