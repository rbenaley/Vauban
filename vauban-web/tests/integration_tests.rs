/// VAUBAN Web - Integration Tests.
///
/// Entry point for all integration tests.
///
/// Run with: cargo test --test integration_tests
///
/// Requirements:
/// - PostgreSQL test database at DATABASE_URL
/// - Run migrations: diesel migration run
// Test modules organized by category
mod api; // REST API tests (/api/v1/*)
mod middleware; // Middleware tests
mod security; // Security tests (auth, CSRF, rate limiting)
mod web; // Web page tests (HTML)
mod ws; // WebSocket tests

// Shared test utilities
mod common;
mod fixtures;

// Re-export for test modules
pub use common::*;
pub use fixtures::*;
