//! Invariants for Kerberos KDC FD-pass (proxy-owned framed I/O).

#![allow(clippy::expect_used)]

use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn check_kerberos_kdc_fd_lint_passes() {
    let script = repo_root().join("scripts/check_kerberos_kdc_fd.sh");
    let status = Command::new("bash")
        .arg(&script)
        .status()
        .expect("run check_kerberos_kdc_fd.sh");
    assert!(status.success(), "check_kerberos_kdc_fd.sh must pass");
}

#[test]
fn main_loop_kdc_response_uses_recv_fd_not_payload() {
    let main_rs = std::fs::read_to_string(repo_root().join("src/main.rs")).expect("main.rs");
    let idx = main_rs
        .find("Message::KerberosKdcResponse")
        .expect("KerberosKdcResponse arm");
    let arm = &main_rs[idx..idx + 600.min(main_rs.len() - idx)];
    assert!(
        arm.contains("recv_fd_timed"),
        "KerberosKdcResponse success path must recv_fd_timed"
    );
    assert!(
        !arm.contains("into_inner()"),
        "KerberosKdcResponse must not treat data as KDC payload"
    );
}

#[test]
fn kdc_pending_keyed_by_request_id_not_session_id_map() {
    let session = std::fs::read_to_string(repo_root().join("src/session.rs")).expect("session.rs");
    assert!(
        session.contains("HashMap<u64, tokio::sync::oneshot::Sender<KdcLeaseResult>>")
            || (session.contains("request_id")
                && session.contains("OwnedFd")
                && session.contains("pending")),
        "KDC lease pending must be request_id-keyed (OwnedFd), not asset session_id map"
    );
    assert!(
        session.contains("SensitiveBytes::default()"),
        "KerberosKdcRequest.data must be empty on the FD-lease path"
    );
}
