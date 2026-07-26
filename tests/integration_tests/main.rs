//! Integration test binary for behavioral pyramid surfaces.
//!
//! Filters:
//! - `cargo test --test integration_tests -- auth_tenant -- --test-threads=1`
//! - `cargo test --test integration_tests -- http_edge -- --test-threads=1`
//! - `cargo test --test integration_tests -- portal_shell -- --test-threads=1`

mod auth_tenant_battle_test;
mod auth_tenant_e2e_test;
mod auth_tenant_invariants_test;
mod auth_tenant_models_test;
mod auth_tenant_proptest;
mod common;
mod http_edge_battle_test;
mod http_edge_e2e_test;
mod http_edge_invariants_test;
mod http_edge_proptest;
mod portal_shell_battle_test;
mod portal_shell_e2e_test;
mod portal_shell_invariants_test;
mod portal_shell_proptest;
