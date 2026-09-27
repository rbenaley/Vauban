// Relax strict clippy lints in test code where unwrap/expect/panic are idiomatic.
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

//! Re-export the shared Mission Seal engine. Live SoT is vauban-access;
//! this crate remains the PEP (and the in-process fallback for tests
//! without AccessGuard).
pub use shared::mcp_mandate::*;
