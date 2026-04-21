//! Shared library for Vauban privilege-separated architecture.
//!
//! This crate provides:
//! - IPC message types for inter-process communication
//! - Unix pipe utilities with SCM_RIGHTS support
//! - Capsicum sandboxing wrappers for FreeBSD

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

pub mod capsicum;
pub mod ipc;
pub mod messages;
pub mod totp;

// Defense-in-depth RBAC re-check helper. Pulled in by every protocol
// proxy (vauban-proxy-ssh, vauban-proxy-rdp, ...) that opens upstream
// sessions on behalf of a user. Behind a feature flag because it brings
// in a tokio dependency that vault/audit/auth must not pay for.
#[cfg(feature = "access-guard")]
pub mod access_guard;

pub use messages::{ControlMessage, Message, ServiceStats};
