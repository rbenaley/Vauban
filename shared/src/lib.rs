//! Shared library for Vauban privilege-separated architecture.
//!
//! This crate provides:
//! - IPC message types for inter-process communication
//! - Unix pipe utilities with SCM_RIGHTS support
//! - Multi-OS process sandbox abstraction (Capsicum / Landlock+seccomp / pledge)

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

pub mod ipc;
pub mod messages;
pub mod privdrop;
pub mod recording_paths;
pub mod sandbox;
pub mod totp;
pub mod username;
pub mod validation;

// Defense-in-depth RBAC re-check helper. Pulled in by every protocol
// proxy (vauban-proxy-ssh, vauban-proxy-rdp, ...) that opens upstream
// sessions on behalf of a user. Behind a feature flag because it brings
// in a tokio dependency that vault/audit/auth must not pay for.
#[cfg(feature = "access-guard")]
pub mod access_guard;

// Cryptographic session-token gate (BLAKE3-keyed MAC binding every
// session-open to a fresh access decision). Pulled in by vauban-access
// (mints), vauban-supervisor and the protocol proxies (verify).
// vauban-web does NOT enable this feature -- it transports the token
// as opaque bytes.
#[cfg(feature = "session-token")]
pub mod session_token;

// Tiny periodic-task helper (Handle-based, runtime-context-free).
// Used by every crate that needs `tokio::time::interval`-driven
// background work without re-implementing the spawn/log/skip-first
// boilerplate. Behind a feature so tokio-free consumers (vault,
// audit, auth) keep their dep tree minimal.
#[cfg(feature = "tasks")]
pub mod tasks;

// IACS sshd Ed25519 host key persistence (load_or_generate_host_key,
// prepare_host_key_fd, read_host_key_from_fd). Pulled in by vauban-
// supervisor (pre-loads the key BEFORE fork and hands the FD to the
// proxy) and by vauban-proxy-iacs (drains the FD BEFORE Capsicum so
// the proxy never opens a path post-`cap_enter`).
#[cfg(feature = "iacs-host-key")]
pub mod iacs_host_key;

// Ed25519 SSH key-pair generation for the asset key-based auth flow
// (generate_ed25519_keypair). Pulled in by vauban-web only (the sole
// generator of asset key-pairs). Behind the `ssh-keygen` feature so
// tokio-free crates that never generate keys keep their dep tree minimal.
#[cfg(feature = "ssh-keygen")]
pub mod ssh_keygen;

// Peek-based industrial wire protocol family classification for the
// IACS tunnel gate. Pulled in by vauban-proxy-iacs only.
#[cfg(feature = "iacs-protocol")]
pub mod iacs_protocol;

// Global client IP allowlist (CIDR ACL). One matcher shared by every
// client-facing entry point so the decision can never drift between
// vauban-web (HTTP/WS middleware) and vauban-proxy-iacs (sshd accept
// loop); vauban-supervisor validates and transports the ranges.
#[cfg(feature = "client-acl")]
pub mod client_acl;

pub use messages::{ControlMessage, Message, ServiceStats};
