//! Integration test binary for the auth/tenant pyramid surface.
//!
//! Filter: `cargo test --test integration_tests -- auth_tenant -- --test-threads=1`

mod auth_tenant_battle_test;
mod auth_tenant_e2e_test;
mod auth_tenant_invariants_test;
mod auth_tenant_models_test;
mod auth_tenant_proptest;
mod common;
