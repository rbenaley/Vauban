//! Shared library for Vauban privilege-separated architecture.
//!
//! This crate provides:
//! - IPC message types for inter-process communication
//! - Unix pipe utilities with SCM_RIGHTS support
//! - Capsicum sandboxing wrappers for FreeBSD

pub mod capsicum;
pub mod ipc;
pub mod messages;

pub use messages::{ControlMessage, Message, ServiceStats};
