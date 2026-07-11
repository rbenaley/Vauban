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
