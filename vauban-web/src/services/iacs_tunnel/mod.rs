//! IACS tunnel orchestration kept inside `vauban-web`.
//!
//! The russh sshd itself lives in the privileged-separated
//! `vauban-proxy-iacs` service. This module only owns the
//! web-side helpers that do not require a live SSH listener:
//!
//! * [`countdown`] -- waiting-client TTL presentation
//! * [`port_mapping`] -- deterministic local-forward port derivation
//! * [`boot_reconcile`] -- boot resync from proxy Snapshot IPC
//! * [`revocation`] -- DB-backed revocation / TTL watchdog (IPC terminate)
//! * [`ws_vocab`] -- SessionLive WebSocket vocabulary shared with
//!   the Alpine status component and the IPC pump
//!
//! Defence-in-depth refusal of non-`direct-tcpip` surfaces is pinned
//! by [`vauban-web/scripts/check_iacs_proxy_no_shell.sh`](../../../../scripts/check_iacs_proxy_no_shell.sh)
//! against `vauban-proxy-iacs/src/server.rs`.

pub mod boot_reconcile;
pub mod countdown;
pub mod port_mapping;
pub mod revocation;
pub mod ws_vocab;

pub use boot_reconcile::{
    BootAction, BootReconcileStats, DbLiveRow, apply_boot_reconcile_plan, is_live_status,
    load_iacs_rows_for_reconcile, phase_to_status, reconcile_iacs_boot,
    reconcile_iacs_from_proxy_snapshot,
};
pub use countdown::{format_countdown_label, remaining_waiting_seconds};
pub use port_mapping::derive_local_forward_port;
pub use revocation::{
    reconcile_orphaned_iacs_tunnels_on_boot, run_once as watchdog_run_once, run_once_with_proxy,
    spawn_watchdog, spawn_watchdog_with_proxy_iacs,
};
