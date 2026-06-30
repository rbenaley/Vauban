//! Source-grep pin tests for the periodic `fdatasync` durability sweep of
//! SSH/RDP recordings (issue: "Durabilite fsync periodique des
//! enregistrements SSH/RDP").
//!
//! These tests are deliberately cross-crate: they `include_str!` the
//! `vauban-audit` and `vauban-supervisor` sources and assert the durability
//! call-graph stays wired, so a future refactor cannot silently drop the
//! `fdatasync` (which would re-open the power-loss data-loss window) or the
//! `VAUBAN_RECORDING_FSYNC_INTERVAL_MS` knob without turning this test red.
//!
//! Companion runtime tests live in `vauban-audit` (`mod tests` of
//! `recording_manager.rs` / `ssh_recording_manager.rs`).

const FMP4_WRITER_SRC: &str = include_str!("../../../vauban-audit/src/fmp4_writer.rs");
const RDP_MGR_SRC: &str = include_str!("../../../vauban-audit/src/recording_manager.rs");
const SSH_MGR_SRC: &str = include_str!("../../../vauban-audit/src/ssh_recording_manager.rs");
const AUDIT_MAIN_SRC: &str = include_str!("../../../vauban-audit/src/main.rs");
const SUPERVISOR_CONFIG_SRC: &str = include_str!("../../../vauban-supervisor/src/config.rs");

const FSYNC_ENV_VAR: &str = "VAUBAN_RECORDING_FSYNC_INTERVAL_MS";

/// The RDP fMP4 writer must expose a `sync()` that forces buffered bytes to
/// disk via `sync_data()` (fdatasync).
#[test]
fn fmp4_writer_sync_calls_fdatasync() {
    assert!(
        FMP4_WRITER_SRC.contains("pub fn sync(&mut self)"),
        "Fmp4Writer::sync() must exist for durable RDP flush"
    );
    assert!(
        FMP4_WRITER_SRC.contains("sync_data()"),
        "Fmp4Writer::sync() must call sync_data() (fdatasync)"
    );
}

/// The RDP recording manager must expose the periodic sweep entry point and
/// reach `fdatasync` both on the periodic path (`writer.sync()`) and when a
/// segment is finalized.
#[test]
fn rdp_manager_wires_sync_dirty_and_fdatasync() {
    assert!(
        RDP_MGR_SRC.contains("pub fn sync_dirty(&mut self) -> SyncStats"),
        "RecordingManager::sync_dirty() must exist"
    );
    assert!(
        RDP_MGR_SRC.contains("writer.sync()"),
        "sync_dirty()/finalize must call the durable Fmp4Writer::sync()"
    );
    // The `dirty` flag drives the idle-skip optimisation.
    assert!(
        RDP_MGR_SRC.contains("dirty"),
        "RecordingManager must track a dirty flag for the sweep"
    );
}

/// The SSH recording manager must expose the periodic sweep and call
/// `sync_data()` (fdatasync) on the periodic path and at end-of-session.
#[test]
fn ssh_manager_wires_sync_dirty_and_fdatasync() {
    assert!(
        SSH_MGR_SRC.contains("pub fn sync_dirty(&mut self) -> SyncStats"),
        "SshRecordingManager::sync_dirty() must exist"
    );
    assert!(
        SSH_MGR_SRC.contains("sync_data()"),
        "SSH sync path must call sync_data() (fdatasync)"
    );
    assert!(
        SSH_MGR_SRC.contains("dirty"),
        "SshRecordingManager must track a dirty flag for the sweep"
    );
}

/// The audit main loop must read the interval env var and drive the sweep
/// (periodic tick + final sweep at shutdown).
#[test]
fn audit_main_reads_interval_and_runs_sweep() {
    assert!(
        AUDIT_MAIN_SRC.contains(FSYNC_ENV_VAR),
        "vauban-audit must read {FSYNC_ENV_VAR}"
    );
    assert!(
        AUDIT_MAIN_SRC.contains("fn run_fsync_sweep("),
        "vauban-audit must define run_fsync_sweep()"
    );
    // Called at least twice: the periodic tick and the shutdown drain.
    assert!(
        AUDIT_MAIN_SRC.matches("run_fsync_sweep(").count() >= 3,
        "run_fsync_sweep must be defined and invoked on both the periodic and \
         shutdown paths"
    );
}

/// The supervisor must emit the interval env var to the audit service so the
/// knob is operator-controllable (and the kill-switch `=0` reachable).
#[test]
fn supervisor_emits_fsync_interval_env_var() {
    assert!(
        SUPERVISOR_CONFIG_SRC.contains(FSYNC_ENV_VAR),
        "supervisor must emit {FSYNC_ENV_VAR} for vauban-audit"
    );
    assert!(
        SUPERVISOR_CONFIG_SRC.contains("fsync_interval_ms"),
        "RecordingConfig must carry fsync_interval_ms"
    );
}
