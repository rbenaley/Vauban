//! VAUBAN Web - Web page handlers.
//!
//! Handlers for serving HTML pages using Askama templates.
//!
//! # SQL Query Guidelines
//!
//! This module primarily uses Diesel DSL for database operations. However, raw SQL
//! queries (`diesel::sql_query`) are used in specific cases where Diesel DSL lacks
//! support or would be overly complex:
//!
//! ## Justified Uses of Raw SQL
//!
//! 1. **Triple JOINs with PostgreSQL-specific casts**: Queries involving multiple
//!    table joins with PostgreSQL type casts like `inet::text` for IP addresses.
//!    Example: Session detail pages joining `proxy_sessions`, `users`, and `assets`.
//!
//! 2. **Subqueries with COUNT(*)**: Aggregation subqueries in SELECT clauses, such
//!    as counting assets per group. Diesel DSL supports simple aggregates but complex
//!    correlated subqueries are clearer in raw SQL.
//!
//! 3. **PostgreSQL-native functions**: Functions like `NOW()`, `INTERVAL`, or
//!    `uuid_generate_v4()` when needed in specific contexts not well-supported by
//!    Diesel helpers.
//!
//! ## Best Practices
//!
//! - Always use parameterized queries (`$1`, `$2`) with `.bind()` to prevent SQL injection
//! - Prefer Diesel DSL for simple CRUD operations (INSERT, UPDATE, DELETE, simple SELECT)
//! - Document why raw SQL is necessary with a `// NOTE:` comment before each `sql_query`
//! - Test all raw SQL queries thoroughly as they are not compile-time checked

// ============================================================================
// Shared imports — re-exported for sub-modules via `use super::*;`
// ============================================================================

pub(crate) use axum::{
    extract::{Form, Query, State},
    response::{Html, IntoResponse, Redirect, Response},
};
pub(crate) use axum_extra::extract::CookieJar;
pub(crate) use diesel::prelude::*;
pub(crate) use diesel::sql_types::{BigInt, Integer, Nullable, Text, Uuid as DieselUuid};
pub(crate) use diesel_async::{AsyncConnection, RunQueryDsl};
pub(crate) use secrecy::ExposeSecret;
pub(crate) use std::collections::HashMap;
pub(crate) use zeroize::Zeroize;

pub(crate) use crate::AppState;
pub(crate) use crate::error::{AppError, AppResult};
pub(crate) use crate::middleware::auth::{AuthUser, OptionalAuthUser, WebAuthUser};
pub(crate) use crate::middleware::flash::{IncomingFlash, flash_redirect};
pub(crate) use crate::schema::{api_keys, assets as schema_assets, auth_sessions, proxy_sessions};
pub(crate) use crate::templates::accounts::{
    ApiKeyItem, ApikeyListTemplate, AuthSessionItem, GroupDetailTemplate, GroupListTemplate,
    LoginTemplate, MfaSetupTemplate, ProfileDetail, ProfileSession, ProfileTemplate,
    SessionListTemplate as AccountSessionListTemplate, UserDetailTemplate, UserListTemplate,
};
pub(crate) use crate::templates::assets::asset_list::AssetListItem;
pub(crate) use crate::templates::assets::{
    AccessListTemplate, AssetDetailTemplate, AssetEditTemplate, AssetGroupDetailTemplate,
    AssetGroupEditTemplate, AssetGroupListTemplate, AssetListTemplate,
};
pub(crate) use crate::templates::base::{BaseTemplate, UserContext};
pub(crate) use crate::templates::dashboard::widgets::{
    ActiveSessionsWidget, RecentActivityWidget, StatsWidget,
};
pub(crate) use crate::templates::dashboard::{AdminTemplate, HomeTemplate};
pub(crate) use crate::templates::sessions::{
    ActiveListTemplate, ApprovalDetailTemplate, ApprovalListTemplate, RecordingListTemplate,
    SessionListTemplate as WebSessionListTemplate,
};
pub(crate) use crate::utils::format_duration;
pub(crate) use askama::Template;

// ============================================================================
// Sub-modules
// ============================================================================

mod assets;
mod asset_groups;
mod dashboard;
mod groups;
mod sessions;
mod ssh;
mod users;

pub use assets::*;
pub use asset_groups::*;
pub use dashboard::*;
pub use groups::*;
pub use sessions::*;
pub use ssh::*;
pub use users::*;

#[cfg(test)]
mod tests;

// ============================================================================
// Shared helpers
// ============================================================================

/// Helper to convert AuthUser to UserContext for templates.
pub(crate) fn user_context_from_auth(auth_user: &AuthUser) -> UserContext {
    UserContext {
        uuid: auth_user.uuid.clone(),
        username: auth_user.username.clone(),
        display_name: auth_user.username.clone(), // TODO: Get full name from database
        is_superuser: auth_user.is_superuser,
        is_staff: auth_user.is_staff,
    }
}

/// Check if the user has admin privileges (superuser or staff).
pub(crate) fn is_admin(auth_user: &WebAuthUser) -> bool {
    auth_user.is_superuser || auth_user.is_staff
}

/// Strip ALL HTML tags from a string to prevent stored XSS.
/// Uses ammonia with an empty tag allowlist so every tag is removed,
/// keeping only the text content.
pub(crate) fn sanitize(value: &str) -> String {
    ammonia::Builder::new()
        .tags(std::collections::HashSet::new())
        .clean(value)
        .to_string()
}

/// Strip ALL HTML tags from an optional string to prevent stored XSS.
pub(crate) fn sanitize_opt(value: Option<String>) -> Option<String> {
    value.map(|s| sanitize(&s))
}

/// Strip ALL HTML tags from an optional string reference to prevent stored XSS.
pub(crate) fn sanitize_opt_ref(value: Option<&String>) -> Option<String> {
    value.map(|s| sanitize(s))
}

/// Build connection_config JSON from SSH credential form fields.
///
/// This stores credentials in the connection_config field of the asset.
/// When vault_client is provided (production), credential fields (password,
/// private_key, passphrase) are encrypted at rest via vauban-vault (C-2).
pub(crate) fn build_connection_config(
    username: Option<&str>,
    auth_type: Option<&str>,
    password: Option<&str>,
    private_key: Option<&str>,
    passphrase: Option<&str>,
) -> serde_json::Value {
    let mut config = serde_json::Map::new();

    // Add username if provided
    if let Some(u) = username.filter(|s| !s.trim().is_empty()) {
        config.insert("username".to_string(), serde_json::Value::String(u.trim().to_string()));
    }

    // Add auth_type if provided
    if let Some(at) = auth_type.filter(|s| !s.trim().is_empty()) {
        config.insert("auth_type".to_string(), serde_json::Value::String(at.to_string()));

        match at {
            "password" => {
                // Add password if auth type is password
                if let Some(p) = password.filter(|s| !s.is_empty()) {
                    config.insert("password".to_string(), serde_json::Value::String(p.to_string()));
                }
            }
            "private_key" => {
                // Add private key if auth type is private_key
                if let Some(pk) = private_key.filter(|s| !s.is_empty()) {
                    config.insert("private_key".to_string(), serde_json::Value::String(pk.to_string()));
                }
                // Add passphrase if provided
                if let Some(pp) = passphrase.filter(|s| !s.is_empty()) {
                    config.insert("passphrase".to_string(), serde_json::Value::String(pp.to_string()));
                }
            }
            _ => {}
        }
    }

    serde_json::Value::Object(config)
}

/// Encrypt credential fields in a connection_config JSON via vault (C-2).
///
/// Encrypts "password", "private_key", and "passphrase" fields in-place.
/// Non-credential fields (username, auth_type, host_key, etc.) are left as-is.
pub(crate) async fn encrypt_connection_config(
    vault: &crate::ipc::VaultCryptoClient,
    config: &mut serde_json::Value,
) -> crate::error::AppResult<()> {
    let credential_fields = ["password", "private_key", "passphrase"];
    if let Some(obj) = config.as_object_mut() {
        for field in &credential_fields {
            if let Some(serde_json::Value::String(val)) = obj.get(*field)
                && !val.is_empty()
                && !is_encrypted(val)
            {
                let encrypted = vault.encrypt("credentials", val).await?;
                obj.insert(field.to_string(), serde_json::Value::String(encrypted));
            }
        }
    }
    Ok(())
}

/// Check whether a value looks like an encrypted ciphertext from vauban-vault.
///
/// Encrypted values have the format `"v{digit(s)}:{base64}"`.
pub(crate) fn is_encrypted(value: &str) -> bool {
    if value.len() < 4 {
        return false;
    }
    if !value.starts_with('v') {
        return false;
    }
    let Some(colon_pos) = value.find(':') else {
        return false;
    };
    if colon_pos < 2 {
        return false;
    }
    value[1..colon_pos].chars().all(|c| c.is_ascii_digit())
}

// ============================================================================
// Generic handlers
// ============================================================================

/// Empty response for HTMX modal close and similar use cases.
/// Returns an empty HTML fragment to clear a target element.
pub async fn htmx_empty() -> Html<&'static str> {
    Html("")
}

/// Fallback handler for unmatched routes.
/// Redirects to the home page instead of returning a 404.
pub async fn fallback_handler() -> Redirect {
    Redirect::to("/")
}

/// Login page.
pub async fn login_page(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<impl IntoResponse, AppError> {
    let base = BaseTemplate::new("Login".to_string(), None);
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        base.into_fields();

    // Get or generate CSRF token
    let secret = state.config.secret_key.expose_secret().as_bytes();
    let (csrf_token, new_cookie) = get_or_create_csrf_token(&jar, secret);

    let template = LoginTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        csrf_token,
    };

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;

    // Return response with updated cookie if a new token was generated
    if let Some(cookie) = new_cookie {
        Ok((jar.add(cookie), Html(html)).into_response())
    } else {
        Ok(Html(html).into_response())
    }
}

/// Get the CSRF token from cookie or generate a new one.
/// Returns the token and optionally a new cookie to set.
fn get_or_create_csrf_token(
    jar: &CookieJar,
    secret: &[u8],
) -> (String, Option<axum_extra::extract::cookie::Cookie<'static>>) {
    use crate::middleware::csrf::{
        CSRF_COOKIE_NAME, build_csrf_cookie, generate_csrf_token, verify_csrf_token,
    };

    // Check if we have a valid existing token
    if let Some(cookie) = jar.get(CSRF_COOKIE_NAME)
        && verify_csrf_token(secret, cookie.value())
    {
        return (cookie.value().to_string(), None);
    }

    // Generate new token
    let token = generate_csrf_token(secret);
    let cookie = build_csrf_cookie(&token);
    (token, Some(cookie))
}
