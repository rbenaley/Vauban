//! VAUBAN Web - API handlers module.
//!
//! Pure M2M (Machine-to-Machine) API handlers returning JSON only.
//! These handlers are separate from web handlers and can be disabled
//! via configuration without affecting web functionality.
//!
//! Key differences from web handlers:
//! - Accept and return JSON only (no HTML, no HTMX)
//! - Use `Json<T>` extractor/response instead of `Form<T>`
//! - Return structured error responses, not flash messages
//! - Authenticated via API keys or JWT tokens
//!
//! Authorization is performed exclusively through the Casbin-backed
//! [`crate::auth::PermissionContext`] extractor: every handler reads the
//! relevant `perms.<resource>_<action>` boolean and returns
//! [`AppError::forbidden`] when the gate is closed. There is no longer a
//! `require_staff` shortcut; handlers must call out the exact permission
//! they require, which is both more granular and more auditable.
//!
//! These handlers are conditionally mounted based on `config.api.enabled`.

pub mod access_rules;
pub mod accounts;
pub mod assets;
pub mod groups;
pub mod manage_assets;
pub mod sessions;
pub mod vault_secrets;

use crate::error::AppError;
use crate::services::api_response_invariants::ApiDenial;

/// Handler served on the whole `/api/v1` tree when the API is disabled
/// by configuration (`[api] enabled = false`).
///
/// INV-API-1: replies `501 Not Implemented` (JSON), NOT a misleading
/// 404 -- the routes exist, the server deliberately does not serve
/// them. A caller probing a disabled bastion learns immediately that
/// the API must be enabled instead of chasing phantom typos.
pub async fn api_disabled_handler() -> AppError {
    ApiDenial::ApiDisabled.into()
}

/// Catch-all router mounted instead of the real API routes when
/// `config.api.enabled` is false. Uses `any()` so EVERY method (GET,
/// POST, PUT, DELETE, PATCH, HEAD, ...) receives the canonical 501,
/// and covers both `/api/v1` and every sub-path.
///
/// Single seam shared by production (`create_app`) and the test router
/// (`tests/common`), so the E2E suite exercises the exact production
/// wiring.
pub fn api_disabled_router() -> axum::Router<crate::AppState> {
    axum::Router::new()
        .route("/api/v1", axum::routing::any(api_disabled_handler))
        .route("/api/v1/{*path}", axum::routing::any(api_disabled_handler))
}

// Re-export all API handlers for convenient access
pub use access_rules::{
    create_access_rule, delete_access_rule, get_access_rule, list_access_rules, update_access_rule,
};
pub use accounts::{create_user, get_user, list_users, update_user};
pub use assets::list_assets;
pub use groups::list_group_members;
pub use manage_assets::{
    create_asset, fetch_rdp_server_cert_api, fetch_ssh_host_key_api, get_asset,
    get_rdp_server_cert_status, get_ssh_host_key_status, list_asset_groups, list_group_assets,
    update_asset,
};
pub use sessions::{create_session, get_session, list_sessions, terminate_session};
pub use vault_secrets::{get_vault_secret, get_vault_secret_value, list_vault_secrets};
