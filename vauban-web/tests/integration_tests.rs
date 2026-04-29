// Integration tests legitimately use unwrap/expect/panic/println
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]

/// VAUBAN Web - Integration Tests.
///
/// Entry point for all integration tests.
///
/// Run with: cargo test --test integration_tests
///
/// Requirements:
/// - PostgreSQL test database at DATABASE_URL (see `config/testing.toml`)
/// - Schema up to date: `diesel migration run` from `vauban-web/` (DDL is not run by tests;
///   runtime DB users are expected to have DML-only privileges).
// Test modules organized by category
mod api; // REST API tests (/api/v1/*)
mod ipc;
mod middleware; // Middleware tests
mod security; // Security tests (auth, CSRF, rate limiting)
mod services; // Service-layer integration tests (DB-only)
mod web; // Web page tests (HTML)
mod ws; // WebSocket tests // IPC integration tests (vauban-access in-process)

// Shared test utilities
mod common;
mod fixtures;

// Re-export for test modules
pub use common::*;
pub use fixtures::*;
