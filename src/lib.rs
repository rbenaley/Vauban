//! Vauban Customer Portal library (Topcoat + Toasty).
//!
//! The binary (`main.rs`) loads config and serves HTTPS. Integration tests
//! under `tests/` exercise the same modules against `vcp_test`.

#![recursion_limit = "256"]

pub mod acme;
pub mod app;
pub mod auth;
pub mod cli;
pub mod companies_accounts;
pub mod companies_search;
pub mod config;
pub mod dashboard_stats;
pub mod db;
pub mod docs_body;
pub mod docs_search;
pub mod docs_version;
pub mod fonts;
pub mod freebsd_pkg;
pub mod http_canonical;
pub mod id_lookups;
pub mod issue_anchor;
pub mod issue_attachments;
pub mod issue_component;
pub mod issue_fsm;
pub mod issue_key;
pub mod issue_status;
pub mod issues_search;
pub mod list_page;
pub mod login_limit;
pub mod magic_link;
pub mod mail_circuit;
pub mod mail_templates;
pub mod mailer;
pub mod models;
pub mod nav;
pub mod perms;
pub mod process_guard;
pub mod release_notes;
pub mod release_pkg;
pub mod seats;
pub mod slug;
pub mod sql_search;
pub mod storage;
pub mod tls;
pub mod tz;
pub mod ui;

#[cfg(test)]
pub mod proptest_util;
