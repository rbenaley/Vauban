//! Source-grep pins for `shared::correlated_ipc` + AccessGuard RbacClient.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

const CORE: &str = include_str!("../src/correlated_ipc.rs");
const ACCESS_GUARD: &str = include_str!("../src/access_guard.rs");
const LIB: &str = include_str!("../src/lib.rs");

#[test]
fn correlated_ipc_module_gated_by_feature() {
    assert!(
        LIB.contains("feature = \"correlated-ipc\""),
        "lib.rs must gate correlated_ipc behind the correlated-ipc feature"
    );
}

#[test]
fn core_documents_consumers_including_supervisor_pending_only() {
    assert!(CORE.contains("RbacClient"));
    assert!(CORE.contains("SupervisorClient"));
    assert!(CORE.contains("PendingGuard"));
    assert!(CORE.contains("process_loop"));
}

#[test]
fn access_guard_rbac_client_has_no_clear_ready() {
    assert!(
        !ACCESS_GUARD.contains("clear_ready"),
        "clear_ready forbidden after RbacClient migration onto try_io"
    );
    assert!(ACCESS_GUARD.contains("CorrelatedIpcCore"));
}
