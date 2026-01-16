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

pub mod accounts;
pub mod assets;
pub mod groups;
pub mod sessions;

// Re-export all API handlers for convenient access
pub use accounts::{create_user, get_user, list_users, update_user};
pub use assets::{create_asset, get_asset, list_assets, update_asset};
pub use groups::list_group_members;
pub use sessions::{create_session, get_session, list_sessions, terminate_session};
