/// VAUBAN Web - API handlers module.
///
/// Pure M2M (Machine-to-Machine) API handlers returning JSON only.
/// These handlers are separate from web handlers and can be disabled
/// via configuration without affecting web functionality.
///
/// Key differences from web handlers:
/// - Accept and return JSON only (no HTML, no HTMX)
/// - Use `Json<T>` extractor/response instead of `Form<T>`
/// - Return structured error responses, not flash messages
/// - Authenticated via API keys or JWT tokens
///
/// These handlers are conditionally mounted based on `config.api.enabled`.

// Re-export existing API handlers from their respective modules
// In the future, these handlers should be moved here and the original
// modules should only contain web-specific handlers.

pub use super::accounts::{create_user, get_user, list_users, update_user};
pub use super::assets::{create_asset, get_asset, list_assets, update_asset};
pub use super::sessions::{create_session, get_session, list_sessions, terminate_session};

// Note: Authentication handlers (login, logout) are special cases that serve
// both web and API clients, so they remain in handlers/auth.rs

#[cfg(test)]
mod tests {
    // API handler tests are in their respective test files:
    // - tests/api/accounts_test.rs
    // - tests/api/assets_test.rs
    // - tests/api/sessions_test.rs
}
