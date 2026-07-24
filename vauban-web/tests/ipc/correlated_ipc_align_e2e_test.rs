//! E2E / API-stability pins for CorrelatedIpc alignment (0.9.31).
//!
//! Public facades (`AccessGuard`, `SupervisorClient::request_*`) must keep
//! their signatures; connect / hydrator suites elsewhere cover live paths.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

const SUPERVISOR: &str = include_str!("../../src/ipc/supervisor.rs");
const ACCESS_GUARD: &str = include_str!("../../../shared/src/access_guard.rs");

#[test]
fn e2e_supervisor_public_request_signatures_unchanged() {
    assert!(
        SUPERVISOR.contains("pub async fn request_tcp_connect("),
        "request_tcp_connect must remain public async"
    );
    assert!(
        SUPERVISOR.contains("pub async fn request_recording_file("),
        "request_recording_file must remain public async"
    );
    assert!(
        SUPERVISOR.contains("pub async fn request_recording_delete("),
        "request_recording_delete must remain public async"
    );
    // session_token argument preserved (INV-CORR-5 style API freeze)
    assert!(
        SUPERVISOR.contains("session_token: Vec<u8>"),
        "request_tcp_connect must still take session_token"
    );
}

#[test]
fn e2e_access_guard_public_surface_unchanged() {
    assert!(
        ACCESS_GUARD.contains("pub fn from_env("),
        "AccessGuard::from_env must remain"
    );
    assert!(
        ACCESS_GUARD.contains("pub fn spawn_dispatcher("),
        "AccessGuard::spawn_dispatcher must remain"
    );
    assert!(
        ACCESS_GUARD.contains("pub async fn authorize("),
        "AccessGuard::authorize must remain"
    );
    assert!(
        ACCESS_GUARD.contains("RBAC_RECHECK_TIMEOUT"),
        "authorize wall-clock timeout constant must remain"
    );
}

#[test]
fn e2e_runbook_smoke_doc_exists() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../docs/runbooks/correlated_ipc_align_smoke_test.md");
    assert!(
        path.exists(),
        "docs/runbooks/correlated_ipc_align_smoke_test.md must exist for 0.9.31"
    );
    let body = std::fs::read_to_string(&path).expect("read runbook");
    for needle in [
        "BLOCKING",
        "0.9.31",
        "AccessGuard",
        "request_tcp_connect",
        "What not to re-litigate",
    ] {
        assert!(body.contains(needle), "runbook must contain '{needle}'");
    }
}
