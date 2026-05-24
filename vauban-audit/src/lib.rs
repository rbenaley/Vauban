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

pub mod iacs_pcap_synth;
pub mod iacs_recording_manager;
