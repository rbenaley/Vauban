//! Shared library for Vauban privilege-separated architecture.
//!
//! This crate provides:
//! - IPC message types for inter-process communication
//! - Unix pipe utilities with SCM_RIGHTS support
//! - Capsicum sandboxing wrappers for FreeBSD

// L-1: Relax strict clippy lints in test code where unwrap/expect/panic are idiomatic
#![cfg_attr(test, allow(
    clippy::unwrap_used, clippy::expect_used, clippy::panic,
    clippy::print_stdout, clippy::print_stderr
))]

pub mod capsicum;
pub mod ipc;
pub mod messages;

pub use messages::{ControlMessage, Message, ServiceStats};
