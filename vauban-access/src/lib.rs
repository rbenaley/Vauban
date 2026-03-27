// L-1: Relax strict clippy lints in test code where unwrap/expect/panic are idiomatic
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

//! Vauban Access Control Service - Library crate
//!
//! Exposes access control logic for in-process use by integration tests.
//! The binary crate (`main.rs`) is the production entry point.

pub mod db;
pub mod handlers;
pub use vauban_db::schema;
