//! Integration test binary for behavioral pyramid surfaces.
//!
//! Filters:
//! - `cargo test --test integration_tests -- auth_tenant -- --test-threads=1`
//! - `cargo test --test integration_tests -- http_edge -- --test-threads=1`
//! - `cargo test --test integration_tests -- portal_shell -- --test-threads=1`
//! - `cargo test --test integration_tests -- admin_docs -- --test-threads=1`
//! - `cargo test --test integration_tests -- portal_issues -- --test-threads=1`
//! - `cargo test --test integration_tests -- admin_releases -- --test-threads=1`
//! - `cargo test --test integration_tests -- admin_companies -- --test-threads=1`
//! - `cargo test --test integration_tests -- builds_entitlement -- --test-threads=1`
//! - `cargo test --test integration_tests -- toasty_filters -- --test-threads=1`
//! - `cargo test --test integration_tests -- toasty_migrations -- --test-threads=1`
//! - `cargo test --test integration_tests -- docs_search_shard -- --test-threads=1`
//! - `cargo test --test integration_tests -- display_tz -- --test-threads=1`

mod admin_companies_battle_test;
mod admin_companies_e2e_test;
mod admin_companies_invariants_test;
mod admin_companies_proptest;
mod admin_docs_battle_test;
mod admin_docs_e2e_test;
mod admin_docs_invariants_test;
mod admin_docs_proptest;
mod admin_releases_battle_test;
mod admin_releases_e2e_test;
mod admin_releases_invariants_test;
mod admin_releases_proptest;
mod auth_tenant_battle_test;
mod auth_tenant_e2e_test;
mod auth_tenant_invariants_test;
mod auth_tenant_models_test;
mod auth_tenant_proptest;
mod builds_entitlement_battle_test;
mod builds_entitlement_e2e_test;
mod builds_entitlement_invariants_test;
mod builds_entitlement_proptest;
mod common;
mod display_tz_battle_test;
mod display_tz_e2e_test;
mod display_tz_invariants_test;
mod display_tz_proptest;
mod docs_search_shard_battle_test;
mod docs_search_shard_e2e_test;
mod docs_search_shard_invariants_test;
mod docs_search_shard_proptest;
mod http_edge_battle_test;
mod http_edge_e2e_test;
mod http_edge_invariants_test;
mod http_edge_proptest;
mod portal_issues_battle_test;
mod portal_issues_e2e_test;
mod portal_issues_invariants_test;
mod portal_issues_proptest;
mod portal_shell_battle_test;
mod portal_shell_e2e_test;
mod portal_shell_invariants_test;
mod portal_shell_proptest;
mod toasty_filters_battle_test;
mod toasty_filters_e2e_test;
mod toasty_filters_invariants_test;
mod toasty_filters_proptest;
mod toasty_migrations_battle_test;
mod toasty_migrations_e2e_test;
mod toasty_migrations_invariants_test;
mod toasty_migrations_proptest;
