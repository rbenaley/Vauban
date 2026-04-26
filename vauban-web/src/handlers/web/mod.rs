//! VAUBAN Web - Web page handlers.
//!
//! Handlers for serving HTML pages using Askama templates.
//!
//! # SQL Query Guidelines
//!
//! This module uses Diesel DSL for all database operations. Triple JOINs, inet/uuid
//! type conversions and LEFT JOINs are all expressed via the DSL, with Rust-side
//! `.to_string()` for `IpNetwork` and `Uuid` values. Explicit `.on()` clauses are
//! used for `proxy_sessions -> users` joins since both `user_id` and `approved_by_id`
//! reference the `users` table (no `joinable!` macro).
//!
//! Raw SQL (`diesel::sql_query`) may still exist in other sub-modules for correlated
//! subqueries or PostgreSQL-native functions. When using raw SQL:
//!
//! - Always use parameterized queries (`$1`, `$2`) with `.bind()` to prevent SQL injection
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
pub(crate) use diesel_async::{AsyncConnection, RunQueryDsl};
pub(crate) use secrecy::ExposeSecret;
pub(crate) use std::collections::HashMap;
pub(crate) use zeroize::Zeroize;

pub(crate) use crate::AppState;
pub(crate) use crate::error::{AppError, AppResult};
pub(crate) use crate::middleware::auth::{AuthUser, WebAuthUser};
pub(crate) use crate::middleware::flash::{IncomingFlash, flash_redirect, htmx_or_flash_redirect};
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

mod access_rules;
mod asset_groups;
mod assets;
mod audit;
mod dashboard;
mod groups;
mod rdp;
mod sessions;
mod ssh;
mod users;

pub use access_rules::*;
pub use asset_groups::*;
pub use assets::*;
pub use audit::*;
pub use dashboard::*;
pub use groups::*;
pub use rdp::*;
pub use sessions::*;
pub use ssh::*;
pub use users::*;

pub const ACCOUNT_DEACTIVATED_MSG: &str = "Your account has been deactivated";

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
        // allow-role-gate: copied verbatim into UserContext for template display (badges, formulaires); not used as a gate.
        is_superuser: auth_user.is_superuser,
        // allow-role-gate: copied verbatim into UserContext for template display (badges, formulaires); not used as a gate.
        is_staff: auth_user.is_staff,
    }
}

/// Apply RBAC-based sidebar permissions to a `BaseTemplate`.
///
/// Loads the canonical [`crate::auth::PermissionContext`] for the user (one
/// parallel `tokio::join!` of every tracked Casbin permission) and:
///
/// 1. Injects it into the sidebar so templates can gate on `sc.perms.*`
///    rather than the `is_staff || is_superuser` shortcut. This is the **only**
///    sidebar RBAC path: there is no longer a parallel set of legacy
///    `can_view_*` booleans to keep in sync.
/// 2. Loads the pending-approval counter when the user is allowed to view
///    the administration section.
pub(crate) async fn apply_sidebar_rbac(
    state: &AppState,
    auth_user: &crate::middleware::auth::AuthUser,
    base: crate::templates::base::BaseTemplate,
) -> crate::templates::base::BaseTemplate {
    let perms = crate::auth::PermissionContext::load(state, auth_user).await;
    let admin = perms.admin_view;
    let mut base = base.with_perms(perms);

    if admin && let Ok(mut conn) = state.db_pool.get().await {
        // Exclude the viewer's own pending requests from the badge:
        // separation of duties forbids self-approval, so a number
        // that included them would be misleading ("you have N to
        // review", when really you can only review N - own).
        use crate::schema::users;
        let viewer_db_id: Option<i32> = match ::uuid::Uuid::parse_str(&auth_user.uuid) {
            Ok(uuid) => users::table
                .filter(users::uuid.eq(uuid))
                .select(users::id)
                .first::<i32>(&mut conn)
                .await
                .ok(),
            Err(_) => None,
        };

        let count: i64 = if let Some(id) = viewer_db_id {
            proxy_sessions::table
                .filter(proxy_sessions::status.eq("pending"))
                .filter(proxy_sessions::user_id.ne(id))
                .count()
                .get_result(&mut conn)
                .await
                .unwrap_or(0)
        } else {
            proxy_sessions::table
                .filter(proxy_sessions::status.eq("pending"))
                .count()
                .get_result(&mut conn)
                .await
                .unwrap_or(0)
        };
        base = base.with_pending_approval_count(count);
    }

    base
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

/// Reject combinations of `asset_type` + auth fields that are nonsensical
/// for the chosen protocol. Returns the user-facing error message that
/// should be surfaced via flash redirect.
///
/// Currently the only forbidden combination is RDP + private-key auth:
///
/// - RDP does not understand SSH key material; storing one would leave a
///   dormant secret on the row that the proxy would never use, and would
///   silently reactivate on the next operator looking at the form (see
///   the SEC-11 carryover scenario closed in this same change).
/// - SSH accepts both `password` and `private_key`, no further check
///   needed at this layer (length validation lives elsewhere).
///
/// We refuse rather than silently strip so an operator who pasted a key
/// learns immediately that the field will not be honoured, instead of
/// discovering the mistake during a later session establishment.
pub(crate) fn validate_auth_inputs(
    asset_type: crate::models::asset::AssetType,
    auth_type: Option<&str>,
    private_key: Option<&str>,
    passphrase: Option<&str>,
) -> Result<(), String> {
    use crate::models::asset::AssetType;

    if asset_type == AssetType::Rdp {
        if matches!(auth_type, Some("private_key")) {
            return Err(
                "Private key authentication is not supported for RDP assets. \
                 Use password authentication instead."
                    .to_string(),
            );
        }
        if private_key.is_some_and(|s| !s.is_empty()) {
            return Err(
                "Private key field is not allowed for RDP assets. Clear it and \
                 retry with password authentication."
                    .to_string(),
            );
        }
        if passphrase.is_some_and(|s| !s.is_empty()) {
            return Err(
                "Passphrase field is not allowed for RDP assets. Clear it and \
                 retry with password authentication."
                    .to_string(),
            );
        }
    }

    Ok(())
}

/// Validate that the credential fields required by the FA `ASS-02`
/// (SSH) and `ASS-03` (RDP) acceptance criteria are actually present.
///
/// `validate_auth_inputs` only catches **forbidden** combinations (e.g.
/// RDP + private key); this helper catches the dual case of
/// **missing** credentials, which `build_connection_config` would
/// otherwise silently drop because every credential field is optional
/// at the JSON layer.
///
/// Per FA §4.4:
///
/// - `ASS-03` (RDP): a row is only operational when it carries a
///   non-empty `password`. Without it, the proxy will either fail the
///   first NLA handshake confusingly or — worse — succeed against an
///   anonymous-allow host, creating an audit gap.
/// - `ASS-02` (SSH): a row needs *either* a non-empty `password` (when
///   `auth_type=password`) *or* a non-empty `private_key` (when
///   `auth_type=private_key`). The default `auth_type` when absent is
///   `password`.
///
/// Trimmed-empty values count as missing on purpose: a single space
/// is never a usable secret and accepting it would let an operator
/// bypass the check by accident.
pub(crate) fn validate_required_credentials(
    asset_type: crate::models::asset::AssetType,
    auth_type: Option<&str>,
    password: Option<&str>,
    private_key: Option<&str>,
) -> Result<(), String> {
    use crate::models::asset::AssetType;

    let is_blank = |o: Option<&str>| o.map(str::trim).is_none_or(str::is_empty);

    match asset_type {
        AssetType::Rdp => {
            if is_blank(password) {
                return Err("Password is required for RDP assets (ASS-03).".to_string());
            }
        }
        AssetType::Ssh => {
            // The form omits `auth_type` only on RDP; an SSH submit
            // without it is a tampered request, but treat it as the
            // documented default for backwards compatibility rather
            // than 500-ing the operator.
            let mode = auth_type.unwrap_or("password");
            match mode {
                "password" => {
                    if is_blank(password) {
                        return Err("Password is required for SSH assets when authentication \
                             type is 'password' (ASS-02)."
                            .to_string());
                    }
                }
                "private_key" => {
                    if is_blank(private_key) {
                        return Err(
                            "Private key is required for SSH assets when authentication \
                             type is 'private_key' (ASS-02)."
                                .to_string(),
                        );
                    }
                }
                other => {
                    return Err(format!(
                        "Unknown SSH authentication type '{}'. Expected 'password' or 'private_key'.",
                        other
                    ));
                }
            }
        }
    }

    Ok(())
}

/// Build connection_config JSON from credential form fields.
///
/// Protocol-aware: the shape of the resulting JSON depends on
/// `asset_type` so the persisted blob never contains keys that the
/// matching proxy would not consume.
///
/// - `Ssh` -> may contain `username`, `auth_type`, `password` (when
///   `auth_type=password`), `private_key` + `passphrase` (when
///   `auth_type=private_key`). `domain` is ignored.
/// - `Rdp` -> may contain `username`, `password`, `domain`. The
///   `auth_type`, `private_key` and `passphrase` arguments are ignored
///   on purpose: callers should have rejected those upstream via
///   `validate_auth_inputs`, and accepting them here would only
///   re-introduce the SEC-11 carryover risk.
///
/// When the `vault_client` is wired in, credential fields are
/// encrypted at rest via `encrypt_connection_config` after this helper
/// returns.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_connection_config(
    asset_type: crate::models::asset::AssetType,
    username: Option<&str>,
    auth_type: Option<&str>,
    password: Option<&str>,
    private_key: Option<&str>,
    passphrase: Option<&str>,
    domain: Option<&str>,
) -> serde_json::Value {
    use crate::models::asset::AssetType;

    let mut config = serde_json::Map::new();

    if let Some(u) = username.filter(|s| !s.trim().is_empty()) {
        config.insert(
            "username".to_string(),
            serde_json::Value::String(u.trim().to_string()),
        );
    }

    match asset_type {
        AssetType::Ssh => {
            if let Some(at) = auth_type.filter(|s| !s.trim().is_empty()) {
                config.insert(
                    "auth_type".to_string(),
                    serde_json::Value::String(at.to_string()),
                );

                match at {
                    "password" => {
                        if let Some(p) = password.filter(|s| !s.is_empty()) {
                            config.insert(
                                "password".to_string(),
                                serde_json::Value::String(p.to_string()),
                            );
                        }
                    }
                    "private_key" => {
                        if let Some(pk) = private_key.filter(|s| !s.is_empty()) {
                            config.insert(
                                "private_key".to_string(),
                                serde_json::Value::String(pk.to_string()),
                            );
                        }
                        if let Some(pp) = passphrase.filter(|s| !s.is_empty()) {
                            config.insert(
                                "passphrase".to_string(),
                                serde_json::Value::String(pp.to_string()),
                            );
                        }
                    }
                    _ => {}
                }
            }
        }
        AssetType::Rdp => {
            // RDP only knows username + password (+ optional Windows
            // domain). `auth_type`, `private_key`, `passphrase` are
            // intentionally dropped here as a defence-in-depth layer
            // behind `validate_auth_inputs` -- a tampered request that
            // bypassed validation still cannot persist SSH key material
            // on an RDP row.
            if let Some(p) = password.filter(|s| !s.is_empty()) {
                config.insert(
                    "password".to_string(),
                    serde_json::Value::String(p.to_string()),
                );
            }
            if let Some(d) = domain.filter(|s| !s.trim().is_empty()) {
                config.insert(
                    "domain".to_string(),
                    serde_json::Value::String(d.trim().to_string()),
                );
            }
        }
    }

    serde_json::Value::Object(config)
}

/// Compute the new `connection_config` for an asset UPDATE, starting
/// from the existing row and overlaying ONLY the fields the operator
/// explicitly re-submitted via the edit form.
///
/// # Why not `build_connection_config` + a narrow patch-back?
///
/// `build_connection_config` was designed for the CREATE flow: it
/// emits a fresh JSON object containing only the fields present on
/// the form. Reusing it for UPDATE forces a "rebuild from scratch
/// then patch back the few fields we care about" pattern, which is
/// fundamentally fragile: every field that the edit form does NOT
/// re-render (today: the entire SSH host-key state — `ssh_host_key`,
/// `ssh_host_key_fingerprint`, `ssh_host_key_mismatch`) is silently
/// dropped on every edit.
///
/// In security terms this destroys host-key pinning (next connection
/// re-pins whatever the server offers, defeating the TOFU guarantee)
/// AND clears any `ssh_host_key_mismatch=true` block previously set
/// by `verify_ssh_host_key` on a suspected MITM — without
/// confirmation, without audit, even when the operator only meant
/// to fix a typo in the description. See GitHub issue #20.
///
/// The fix here is structural: start from `existing` and overlay,
/// instead of build-from-scratch and patch-back. Any field absent
/// from the form (whether because we don't render it today, or
/// because a future schema migration adds a new key) round-trips
/// untouched by construction.
///
/// # Form-field semantics (matches `asset_edit.html`)
///
/// - `username`, `auth_type`: **present-but-empty ⇒ keep existing**
///   (option A; the form always renders these inputs).
/// - `password`, `private_key`, `passphrase`: **present-but-empty ⇒
///   keep existing** (option A; the stored ciphertext is never
///   round-tripped through the browser, so the input is intentionally
///   rendered blank with a "Leave blank to keep current" hint).
/// - `domain` (RDP): **`Some("")` ⇒ clear it** (it's a regular text
///   input the operator can deliberately empty to remove a domain);
///   **`None` ⇒ keep existing** (defensive: a non-browser client
///   may not send the field at all).
///
/// # Cross-protocol cleanup (defense in depth)
///
/// - SSH ⇒ strip `domain` (RDP-only).
/// - RDP ⇒ strip `auth_type`, `private_key`, `passphrase` (SSH-only).
///
/// This mirrors the protocol-purity guarantee `build_connection_config`
/// provided behind `validate_auth_inputs`: a tampered request that
/// smuggles cross-protocol fields cannot persist them.
///
/// # Encryption
///
/// Plaintext credentials inserted here are encrypted downstream by
/// `encrypt_connection_config`; existing ciphertext copied from
/// `existing` round-trips untouched via `is_encrypted`, so a
/// description-only edit does not re-encrypt (and therefore does not
/// rotate) any credential.
#[allow(clippy::too_many_arguments)]
pub(crate) fn compute_updated_connection_config(
    existing: &serde_json::Value,
    asset_type: crate::models::asset::AssetType,
    username: Option<&str>,
    auth_type: Option<&str>,
    password: Option<&str>,
    private_key: Option<&str>,
    passphrase: Option<&str>,
    domain: Option<&str>,
) -> serde_json::Value {
    use crate::models::asset::AssetType;

    // Start from the existing config so any field NOT mentioned below
    // (notably `ssh_host_key`, `ssh_host_key_fingerprint`,
    // `ssh_host_key_mismatch`, plus any forward-compat keys we don't
    // yet know about) round-trips untouched.
    let mut obj = existing.as_object().cloned().unwrap_or_default();

    let trimmed_nonempty = |o: Option<&str>| {
        o.map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };

    // username: option A (blank or absent ⇒ keep existing).
    if let Some(u) = trimmed_nonempty(username) {
        obj.insert("username".to_string(), serde_json::Value::String(u));
    }

    match asset_type {
        AssetType::Ssh => {
            // RDP-only field must not exist on an SSH row.
            obj.remove("domain");

            // auth_type: option A.
            if let Some(at) = trimmed_nonempty(auth_type) {
                obj.insert("auth_type".to_string(), serde_json::Value::String(at));
            }

            // password / private_key / passphrase: option A.
            // Non-empty values are inserted as plaintext here and
            // encrypted downstream by `encrypt_connection_config`.
            if let Some(p) = password.filter(|s| !s.is_empty()) {
                obj.insert(
                    "password".to_string(),
                    serde_json::Value::String(p.to_string()),
                );
            }
            if let Some(pk) = private_key.filter(|s| !s.is_empty()) {
                obj.insert(
                    "private_key".to_string(),
                    serde_json::Value::String(pk.to_string()),
                );
            }
            if let Some(pp) = passphrase.filter(|s| !s.is_empty()) {
                obj.insert(
                    "passphrase".to_string(),
                    serde_json::Value::String(pp.to_string()),
                );
            }
        }
        AssetType::Rdp => {
            // SSH-only fields must not exist on an RDP row.
            obj.remove("auth_type");
            obj.remove("private_key");
            obj.remove("passphrase");

            // password: option A.
            if let Some(p) = password.filter(|s| !s.is_empty()) {
                obj.insert(
                    "password".to_string(),
                    serde_json::Value::String(p.to_string()),
                );
            }

            // domain: `Some("")` ⇒ clear; `None` ⇒ keep existing.
            if let Some(d) = domain {
                let trimmed = d.trim();
                if trimmed.is_empty() {
                    obj.remove("domain");
                } else {
                    obj.insert(
                        "domain".to_string(),
                        serde_json::Value::String(trimmed.to_string()),
                    );
                }
            }
        }
    }

    serde_json::Value::Object(obj)
}

/// Encrypt credential fields in a connection_config JSON via vault.
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
