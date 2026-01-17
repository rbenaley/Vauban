/// VAUBAN Web - Integration Tests.
///
/// Entry point for all integration tests.
///
/// Run with: cargo test --test integration_tests
///
/// Requirements:
/// - PostgreSQL test database at DATABASE_URL
/// - Run migrations: diesel migration run
mod api;
mod common;
mod fixtures;
mod ws;

// Re-export for test modules
pub use common::*;
pub use fixtures::*;
