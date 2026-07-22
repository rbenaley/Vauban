//! Public surface of `vauban-audit` re-exposed so the binary's
//! integration tests under `tests/` can drive the recording
//! managers without parsing IPC frames over a real Unix socket.
//!
//! `main.rs` is the production entry point and continues to own
//! the `[[bin]]` target; it simply re-uses these modules through
//! `crate::iacs_recording_manager::*` etc.

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::print_stdout,
        clippy::print_stderr
    )
)]

pub mod iacs_gzip_worker;
pub mod iacs_pcap_synth;
pub mod iacs_recording_manager;
pub mod mfa_hol_budget;
pub mod worm;

pub use iacs_gzip_worker::{
    GzipCpuJob, GzipCpuOutcome, PendingGzipTracker, drain_wakeup, run_gzip_cpu, spawn_gzip_worker,
    wakeup_pipe,
};

pub use mfa_hol_budget::{
    SUPERVISOR_BROKER_TIMEOUT_SECS, WEB_CRITICAL_ACK_TIMEOUT_SECS,
    broker_timeout_fits_under_critical_ack, production_broker_budget_is_safe,
};
