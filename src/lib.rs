//! Vauban Customer Portal library (Topcoat + Toasty).
//!
//! The binary (`main.rs`) loads config and serves HTTPS. Integration tests
//! under `tests/` exercise the same modules against `vcp_test`.

#![recursion_limit = "256"]

pub mod acme;
pub mod app;
pub mod auth;
pub mod config;
pub mod db;
pub mod layout;
pub mod models;
pub mod perms;
pub mod tls;
pub mod ui;
