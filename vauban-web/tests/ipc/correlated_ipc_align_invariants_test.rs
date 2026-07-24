//! Source-pin invariants for CorrelatedIpc alignment (0.9.31).
//!
//! Core lives in `shared::correlated_ipc`; RbacClient uses try_io;
//! SupervisorClient uses PendingGuard only (no AsyncFd rewrite).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

const SHARED_CORE: &str = include_str!("../../../shared/src/correlated_ipc.rs");
const ACCESS_GUARD: &str = include_str!("../../../shared/src/access_guard.rs");
const WEB_REEXPORT: &str = include_str!("../../src/ipc/correlated.rs");
const SUPERVISOR: &str = include_str!("../../src/ipc/supervisor.rs");

#[test]
fn core_lives_in_shared_correlated_ipc() {
    assert!(
        SHARED_CORE.contains("fn process_loop"),
        "AsyncFd core must live in shared/src/correlated_ipc.rs"
    );
    assert!(SHARED_CORE.contains("try_io"));
    assert!(SHARED_CORE.contains("struct PendingGuard"));
    assert!(SHARED_CORE.contains("INV-CORR-5"));
    assert!(
        WEB_REEXPORT.contains("shared::correlated_ipc"),
        "web correlated.rs must re-export shared::correlated_ipc"
    );
}

#[test]
fn rbac_client_uses_try_io_pending_guard_not_clear_ready() {
    assert!(
        !ACCESS_GUARD.contains("clear_ready"),
        "RbacClient dispatcher must not use clear_ready (try_io via core)"
    );
    assert!(
        ACCESS_GUARD.contains("CorrelatedIpcCore"),
        "RbacClient must compose CorrelatedIpcCore"
    );
    assert!(
        ACCESS_GUARD.contains(".process_loop(") || ACCESS_GUARD.contains("process_loop(|"),
        "RbacClient must call process_loop"
    );
    assert!(
        ACCESS_GUARD.contains(".request("),
        "check_access_by_uuid must use core.request"
    );
}

#[test]
fn supervisor_pending_guard_only_no_asyncfd() {
    // Production body only (unit-test module may mention AsyncFd in pins).
    let prod = SUPERVISOR.split("#[cfg(test)]").next().expect("split");
    assert!(
        prod.contains("CorrelatedIpcCore::insert_pending"),
        "SupervisorClient must install PendingGuard via insert_pending"
    );
    assert!(prod.matches("CorrelatedIpcCore::insert_pending").count() >= 3);
    assert!(
        !prod.contains("AsyncFd::"),
        "SupervisorClient must not use AsyncFd"
    );
    let forbidden = format!(".{}(", "process_loop");
    assert!(
        !prod.contains(&forbidden),
        "SupervisorClient must not call process_loop"
    );
    assert!(
        prod.contains("PendingGuard hygiene"),
        "module must document PendingGuard-only alignment"
    );
}

#[test]
fn check_ipc_correlated_core_script_passes() {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("scripts/check_ipc_correlated_core.sh");
    let out = std::process::Command::new("bash")
        .arg(&script)
        .output()
        .expect("run lint");
    assert!(
        out.status.success(),
        "check_ipc_correlated_core.sh failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn check_supervisor_ipc_pending_guard_script_passes() {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("scripts/check_supervisor_ipc_pending_guard.sh");
    assert!(script.exists(), "supervisor pending-guard lint must exist");
    let out = std::process::Command::new("bash")
        .arg(&script)
        .output()
        .expect("run lint");
    assert!(
        out.status.success(),
        "check_supervisor_ipc_pending_guard.sh failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
