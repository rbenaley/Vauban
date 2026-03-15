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
//! These handlers are conditionally mounted based on `config.api.enabled`.

pub mod access_rules;
pub mod accounts;
pub mod assets;
pub mod groups;
pub mod sessions;

use crate::AppState;
use crate::error::AppError;
use crate::middleware::auth::AuthUser;

/// Verify the authenticated user has staff or superuser privileges.
///
/// Uses the RBAC IPC client (Casbin) when available, otherwise falls back
/// to the local `is_staff || is_superuser` check.
/// Returns `Err(AppError::Authorization)` with a 403 Forbidden if the user
/// does not have sufficient privileges.
pub async fn require_staff(state: &AppState, user: &AuthUser) -> Result<(), AppError> {
    let allowed = crate::handlers::web::check_rbac(state, user, "admin", "view").await;
    if allowed {
        Ok(())
    } else {
        Err(AppError::Authorization(
            "Insufficient privileges: staff or superuser role required".to_string(),
        ))
    }
}

// Re-export all API handlers for convenient access
pub use access_rules::{
    create_access_rule, delete_access_rule, get_access_rule, list_access_rules, update_access_rule,
};
pub use accounts::{create_user, get_user, list_users, update_user};
pub use assets::{
    create_asset, fetch_ssh_host_key_api, get_asset, get_ssh_host_key_status, list_asset_groups,
    list_assets, list_group_assets, update_asset,
};
pub use groups::list_group_members;
pub use sessions::{create_session, get_session, list_sessions, terminate_session};
