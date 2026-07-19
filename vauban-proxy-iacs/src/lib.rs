// Relax strict clippy lints in test code where unwrap/expect/panic are idiomatic
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

//! Library facade for `vauban-proxy-iacs`.
//!
//! The crate ships primarily as the `vauban-proxy-iacs` binary
//! (`src/main.rs`), which owns the Capsicum sandbox setup, the FD
//! inheritance plumbing and the supervisor/web IPC loop. Those pieces
//! cannot run outside the privileged supervisor handshake, so they
//! stay in the binary.
//!
//! This `lib.rs` re-exposes the pure, sandbox-independent building
//! blocks (the russh `Server`/`Handler`, the in-memory registries, the
//! relay and the protocol gate) so the integration tests can drive a
//! REAL russh handshake against the production
//! [`server::IacsTunnelServer`] -- the same code path the binary runs,
//! not a mirror. Before this facade existed the server handler was only
//! covered by source-grep pin tests; the handshake itself was never
//! exercised against this binary's code (only against the now-removed
//! in-process copy that lived in `vauban-web`).
//!
//! `main.rs` keeps its own `mod` declarations and is compiled
//! independently of this library; the two share the same source files
//! but are distinct crates. Keeping `main.rs` untouched preserves every
//! `src/main.rs` source-grep invariant asserted by the `tests/` suite.

pub mod auth;
pub mod iacs_recording;
pub mod ipc;
pub mod protocol_gate;
pub mod registry;
pub mod relay;
pub mod server;
pub mod stats;
pub mod upstream;
