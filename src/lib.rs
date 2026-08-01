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
pub mod docs_body;
pub mod docs_search;
pub mod docs_version;
pub mod fonts;
pub mod http_canonical;
pub mod issue_status;
pub mod issues_search;
pub mod list_page;
pub mod login_limit;
pub mod models;
pub mod nav;
pub mod perms;
pub mod release_pkg;
pub mod seats;
pub mod slug;
pub mod tls;
pub mod tz;
pub mod ui;
