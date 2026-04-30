//! Admin "Manage Assets" JSON API handlers — issue #27 asset zone split.
//!
//! Routes mounted under `/api/v1/assets/manage/*` and gated by
//! [`PermissionContext::assets_manage`]. The user-zone `list_assets`
//! (under `/api/v1/assets`) lives in [`crate::handlers::api::assets`]
//! and is gated by `assets_read` instead.
//!
//! # Defence-in-depth
//!
//! Every public handler in this module asserts `perms.assets_manage` at
//! the top of its body, regardless of routing-level middleware. The
//! double-check guarantees:
//!
//! - if a future route registration leaks one of these handlers outside
//!   the `/api/v1/assets/manage` sub-tree, the gate still holds;
//! - the per-route 403 happens **before** any DB lookup, so a
//!   `role:user` cannot enumerate asset existence by probing the
//!   admin endpoints.
//!
//! # No session can ever be opened from this module
//!
//! Source-level CI tests in
//! `tests/web/manage_assets_no_session_test.rs` enforce that this file
//! never references session-opening tokens (`connect-rdp`,
//! `connect_ssh`, `submit_access_request`, `wss://`, etc.).
use ::uuid::Uuid;
use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use serde::Deserialize;

use crate::AppState;
use crate::auth::PermissionContext;
use crate::error::{AppError, AppResult};
use crate::middleware::auth::AuthUser;
use crate::models::asset::{
    Asset, AssetGroup, AssetType, CreateAssetRequest, NewAsset, NewAssetAssetGroup,
    UpdateAssetRequest,
};
use crate::schema::asset_asset_groups::dsl as aag;
use crate::schema::assets::dsl::*;

/// Get asset by UUID handler (admin zone).
///
/// Gated by `assets_manage`. The user-zone listing
/// (`GET /api/v1/assets`) does not include a per-asset detail
/// endpoint by design — there is no detail page in the user zone
/// either.
pub async fn get_asset(
    State(state): State<AppState>,
    _user: AuthUser,
    perms: PermissionContext,
    Path(asset_uuid_str): Path<String>,
) -> AppResult<Json<Asset>> {
    if !perms.assets_manage {
        return Err(AppError::forbidden("assets:manage"));
    }

    let asset_uuid = Uuid::parse_str(&asset_uuid_str)
        .map_err(|_| AppError::Validation("Invalid UUID format".to_string()))?;

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;
    let asset = assets
        .filter(uuid.eq(asset_uuid))
        .filter(is_deleted.eq(false))
        .first::<Asset>(&mut conn)
        .await
        .map_err(|e| match e {
            diesel::result::Error::NotFound => AppError::NotFound("Asset not found".to_string()),
            _ => AppError::Database(e),
        })?;

    Ok(Json(asset))
}

/// Create asset handler (admin zone).
pub async fn create_asset(
    State(state): State<AppState>,
    _user: AuthUser,
    perms: PermissionContext,
    Json(request): Json<CreateAssetRequest>,
) -> AppResult<Json<Asset>> {
    if !perms.assets_manage {
        return Err(AppError::forbidden("assets:manage"));
    }

    validator::Validate::validate(&request)
        .map_err(|e| AppError::Validation(format!("Validation failed: {:?}", e)))?;

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    let default_port = request.port.unwrap_or(request.asset_type.default_port());

    let strip = |s: &str| -> String {
        ammonia::Builder::new()
            .tags(std::collections::HashSet::new())
            .clean(s)
            .to_string()
    };
    let sanitized_name = strip(&request.name);
    let sanitized_description = request.description.map(|d| strip(&d));

    let mut group_ids: Vec<i32> = request.group_ids.clone();
    if let Some(single) = request.group_id
        && group_ids.is_empty()
    {
        group_ids.push(single);
    }
    if !state.config.assets.allow_multiple_groups_per_asset && group_ids.len() > 1 {
        return Err(AppError::Validation(
            "Only one asset group is allowed when allow_multiple_groups_per_asset is false"
                .to_string(),
        ));
    }

    let new_asset = NewAsset {
        uuid: Uuid::new_v4(),
        name: sanitized_name,
        hostname: request.hostname,
        port: default_port,
        asset_type: request.asset_type,
        status: "unknown".to_string(),
        description: sanitized_description,
        connection_config: serde_json::json!({}),
        created_by_id: None,
        connection_username: "root".to_string(),
    };

    // Issue #17: a UniqueViolation here means an active asset on the
    // same (hostname, port, connection_username) triplet already exists.
    // Tombstones do NOT count (the partial unique index only covers
    // active rows), so a 409 here is always a true active-vs-active
    // collision.
    let asset: Asset = diesel::insert_into(assets)
        .values(&new_asset)
        .get_result(&mut conn)
        .await
        .map_err(|e| match e {
            diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UniqueViolation,
                _,
            ) => AppError::Conflict(
                "An asset with this hostname, port and username already exists".to_string(),
            ),
            other => AppError::Database(other),
        })?;

    for gid in group_ids {
        diesel::insert_into(aag::asset_asset_groups)
            .values(NewAssetAssetGroup {
                asset_id: asset.id,
                asset_group_id: gid,
            })
            .execute(&mut conn)
            .await
            .map_err(AppError::Database)?;
    }

    Ok(Json(asset))
}

/// Update asset handler (admin zone).
///
/// Supports HTMX requests by returning:
/// - HX-Redirect header on success (HTMX will redirect automatically)
/// - HTML error fragment on failure (for display in error container)
pub async fn update_asset(
    State(state): State<AppState>,
    _user: AuthUser,
    perms: PermissionContext,
    headers: HeaderMap,
    Path(asset_uuid_str): Path<String>,
    Json(request): Json<UpdateAssetRequest>,
) -> Response {
    use crate::error::{htmx_error_response, is_htmx_request};

    if !perms.assets_manage {
        return AppError::forbidden("assets:manage").into_response();
    }

    let is_htmx = is_htmx_request(&headers);

    macro_rules! handle_error {
        ($status:expr, $msg:expr) => {
            if is_htmx {
                return htmx_error_response($status, $msg).into_response();
            } else {
                return AppError::Validation($msg.to_string()).into_response();
            }
        };
    }

    let asset_uuid = match Uuid::parse_str(&asset_uuid_str) {
        Ok(parsed_uuid) => parsed_uuid,
        Err(_) => {
            handle_error!(StatusCode::BAD_REQUEST, "Invalid UUID format");
        }
    };

    if let Err(e) = validator::Validate::validate(&request) {
        let msg = format!("Validation failed: {:?}", e);
        if is_htmx {
            return htmx_error_response(StatusCode::BAD_REQUEST, &msg).into_response();
        } else {
            return AppError::Validation(msg).into_response();
        }
    }

    let mut conn = match state.db_pool.get().await {
        Ok(c) => c,
        Err(e) => return AppError::Internal(anyhow::anyhow!("DB error: {}", e)).into_response(),
    };

    use crate::schema::assets::dsl::{
        assets, description as description_col, hostname as hostname_col, name as name_col,
        port as port_col, status as status_col, updated_at, uuid,
    };
    use chrono::Utc;

    let existing: Asset = match assets.filter(uuid.eq(asset_uuid)).first(&mut conn).await {
        Ok(a) => a,
        Err(_) => {
            handle_error!(StatusCode::NOT_FOUND, "Asset not found");
        }
    };

    let strip = |s: &str| -> String {
        ammonia::Builder::new()
            .tags(std::collections::HashSet::new())
            .clean(s)
            .to_string()
    };
    let sanitized_name = request.name.map(|n| strip(&n)).unwrap_or(existing.name);
    let sanitized_description = request
        .description
        .map(|d| strip(&d))
        .or(existing.description);

    let asset: Asset = match diesel::update(assets.filter(uuid.eq(asset_uuid)))
        .set((
            name_col.eq(sanitized_name),
            hostname_col.eq(request.hostname.unwrap_or(existing.hostname)),
            port_col.eq(request.port.unwrap_or(existing.port)),
            status_col.eq(request.status.unwrap_or(existing.status)),
            description_col.eq(sanitized_description),
            updated_at.eq(Utc::now()),
        ))
        .get_result(&mut conn)
        .await
    {
        Ok(a) => a,
        Err(e) => {
            tracing::error!("Database error updating asset: {}", e);
            handle_error!(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database operation failed"
            );
        }
    };

    if is_htmx {
        let mut response_headers = HeaderMap::new();
        // SAFETY: asset_uuid is a valid UUID which produces valid ASCII when formatted
        #[allow(clippy::expect_used)]
        let redirect_value = format!("/assets/manage/{}", asset_uuid)
            .parse()
            .expect("UUID format produces valid header value");
        response_headers.insert("HX-Redirect", redirect_value);
        (response_headers, Json(asset)).into_response()
    } else {
        Json(asset).into_response()
    }
}

// =============================================================================
// Asset Groups API (admin zone)
// =============================================================================

/// Query parameters for list asset groups.
#[derive(Debug, Deserialize)]
pub struct ListAssetGroupsParams {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Asset group response for API.
#[derive(Debug, serde::Serialize)]
pub struct AssetGroupResponse {
    pub uuid: Uuid,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub color: String,
    pub icon: String,
    pub asset_count: i64,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// List asset groups handler (admin zone).
pub async fn list_asset_groups(
    State(state): State<AppState>,
    _user: AuthUser,
    perms: PermissionContext,
    Query(params): Query<ListAssetGroupsParams>,
) -> AppResult<Json<Vec<AssetGroupResponse>>> {
    if !perms.assets_manage {
        return Err(AppError::forbidden("assets:manage"));
    }

    use crate::schema::asset_asset_groups::dsl as aag;
    use crate::schema::asset_groups::dsl as ag;
    use crate::schema::assets::dsl as a;

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    let groups: Vec<AssetGroup> = ag::asset_groups
        .filter(ag::is_deleted.eq(false))
        .order(ag::name.asc())
        .limit(params.limit.unwrap_or(100))
        .offset(params.offset.unwrap_or(0))
        .load(&mut conn)
        .await?;

    let mut response: Vec<AssetGroupResponse> = Vec::with_capacity(groups.len());
    for group in groups {
        let asset_count: i64 = aag::asset_asset_groups
            .inner_join(a::assets.on(aag::asset_id.eq(a::id)))
            .filter(aag::asset_group_id.eq(group.id))
            .filter(a::is_deleted.eq(false))
            .count()
            .get_result(&mut conn)
            .await?;

        response.push(AssetGroupResponse {
            uuid: group.uuid,
            name: group.name,
            slug: group.slug,
            description: group.description,
            color: group.color,
            icon: group.icon,
            asset_count,
            created_at: group.created_at,
            updated_at: group.updated_at,
        });
    }

    Ok(Json(response))
}

/// Asset summary for group assets list.
#[derive(Debug, serde::Serialize)]
pub struct GroupAssetResponse {
    pub uuid: Uuid,
    pub name: String,
    pub hostname: String,
    pub port: i32,
    pub asset_type: String,
    pub status: String,
    pub description: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Query parameters for list group assets.
#[derive(Debug, Deserialize)]
pub struct ListGroupAssetsParams {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// List assets in a specific asset group (admin zone).
pub async fn list_group_assets(
    State(state): State<AppState>,
    _user: AuthUser,
    perms: PermissionContext,
    Path(group_uuid_str): Path<String>,
    Query(params): Query<ListGroupAssetsParams>,
) -> AppResult<Json<Vec<GroupAssetResponse>>> {
    if !perms.assets_manage {
        return Err(AppError::forbidden("assets:manage"));
    }

    use crate::schema::asset_asset_groups::dsl as aag;
    use crate::schema::asset_groups::dsl as ag;
    use crate::schema::assets::dsl as a;

    let group_uuid = Uuid::parse_str(&group_uuid_str)
        .map_err(|_| AppError::Validation("Invalid UUID format".to_string()))?;

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    let group: AssetGroup = ag::asset_groups
        .filter(ag::uuid.eq(group_uuid))
        .filter(ag::is_deleted.eq(false))
        .first(&mut conn)
        .await
        .map_err(|e| match e {
            diesel::result::Error::NotFound => {
                AppError::NotFound("Asset group not found".to_string())
            }
            _ => AppError::Database(e),
        })?;

    let group_assets: Vec<Asset> = a::assets
        .inner_join(aag::asset_asset_groups.on(a::id.eq(aag::asset_id)))
        .filter(aag::asset_group_id.eq(group.id))
        .filter(a::is_deleted.eq(false))
        .order(a::name.asc())
        .select(Asset::as_select())
        .limit(params.limit.unwrap_or(100))
        .offset(params.offset.unwrap_or(0))
        .load(&mut conn)
        .await?;

    let response: Vec<GroupAssetResponse> = group_assets
        .into_iter()
        .map(|asset| GroupAssetResponse {
            uuid: asset.uuid,
            name: asset.name,
            hostname: asset.hostname,
            port: asset.port,
            asset_type: asset.asset_type.to_string(),
            status: asset.status,
            description: asset.description,
            created_at: asset.created_at,
            updated_at: asset.updated_at,
        })
        .collect();

    Ok(Json(response))
}

/// Fetch SSH host key API endpoint (admin zone).
///
/// POST /api/v1/assets/manage/{uuid}/ssh-host-key
///
/// Fetches the SSH host key from the remote server and returns it as
/// JSON. If a key was already stored and the new key differs, the
/// response includes a `key_changed` flag set to `true` and both
/// fingerprints. In that case the stored key is NOT updated unless
/// `?confirm=true` is passed. Requires `assets_manage`.
pub async fn fetch_ssh_host_key_api(
    State(state): State<AppState>,
    user: AuthUser,
    perms: PermissionContext,
    Path(asset_uuid_str): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> AppResult<Json<serde_json::Value>> {
    if !perms.assets_manage {
        return Err(AppError::forbidden("assets:manage"));
    }

    let confirm = params.get("confirm").map(|v| v == "true").unwrap_or(false);

    let asset_uuid = Uuid::parse_str(&asset_uuid_str)
        .map_err(|_| AppError::Validation("Invalid UUID format".to_string()))?;

    let proxy_client = state
        .ssh_proxy
        .as_ref()
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("SSH proxy not available")))?;

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    let asset: Asset = assets
        .filter(uuid.eq(asset_uuid))
        .filter(is_deleted.eq(false))
        .first::<Asset>(&mut conn)
        .await
        .map_err(|e| match e {
            diesel::result::Error::NotFound => AppError::NotFound("Asset not found".to_string()),
            _ => AppError::Database(e),
        })?;

    if asset.asset_type != AssetType::Ssh {
        return Err(AppError::Validation(
            "Host key fetch is only available for SSH assets".to_string(),
        ));
    }

    let stored_host_key = asset
        .connection_config
        .get("ssh_host_key")
        .and_then(|v| v.as_str())
        .map(String::from);
    let stored_fingerprint = asset
        .connection_config
        .get("ssh_host_key_fingerprint")
        .and_then(|v| v.as_str())
        .map(String::from);

    // In sandboxed mode (Capsicum), the supervisor brokers the TCP
    // connection and passes the FD to the SSH proxy via SCM_RIGHTS.
    let supervisor_ref = state.supervisor.as_deref();
    let asset_uuid_str_for_token = asset_uuid.to_string();
    let identity = crate::ipc::HostKeyFetchIdentity {
        access_client: state.access_client.as_ref(),
        user_uuid: &user.uuid,
        asset_uuid: &asset_uuid_str_for_token,
    };
    let (host_key, fingerprint) = proxy_client
        .fetch_host_key(
            &asset.hostname,
            asset.port as u16,
            supervisor_ref,
            Some(identity),
        )
        .await?;

    if let Some(ref old_key) = stored_host_key
        && old_key != &host_key
        && !confirm
    {
        let old_fp = stored_fingerprint.as_deref().unwrap_or("unknown");
        tracing::warn!(
            asset_uuid = %asset_uuid,
            old_fingerprint = %old_fp,
            new_fingerprint = %fingerprint,
            "SSH host key CHANGED on remote server - possible MITM attack"
        );
        return Ok(Json(serde_json::json!({
            "success": false,
            "key_changed": true,
            "old_fingerprint": old_fp,
            "new_fingerprint": fingerprint,
            "message": "The remote server's SSH host key has changed. \
                This could indicate a man-in-the-middle attack. \
                Pass ?confirm=true to accept the new key."
        })));
    }

    let mut config = asset.connection_config.clone();
    config["ssh_host_key"] = serde_json::Value::String(host_key.clone());
    config["ssh_host_key_fingerprint"] = serde_json::Value::String(fingerprint.clone());
    config
        .as_object_mut()
        .map(|m| m.remove("ssh_host_key_mismatch"));

    use crate::schema::assets::dsl::connection_config as config_col;
    use crate::schema::assets::dsl::updated_at;
    use chrono::Utc;

    diesel::update(assets.filter(uuid.eq(asset_uuid)))
        .set((config_col.eq(&config), updated_at.eq(Utc::now())))
        .execute(&mut conn)
        .await?;

    Ok(Json(serde_json::json!({
        "success": true,
        "host_key": host_key,
        "fingerprint": fingerprint,
    })))
}

/// Get the SSH host key verification status for an asset (admin zone).
///
/// GET /api/v1/assets/manage/{uuid}/ssh-host-key
///
/// Returns a JSON object with one of three statuses:
/// - `"verified"`: a host key is stored and no mismatch has been detected.
/// - `"mismatch"`: a host key is stored but a connection attempt detected
///   that the server's key has changed.
/// - `"no_key"`: no host key has been stored yet.
pub async fn get_ssh_host_key_status(
    State(state): State<AppState>,
    _user: AuthUser,
    perms: PermissionContext,
    Path(asset_uuid_str): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    if !perms.assets_manage {
        return Err(AppError::forbidden("assets:manage"));
    }

    let asset_uuid = Uuid::parse_str(&asset_uuid_str)
        .map_err(|_| AppError::Validation("Invalid UUID format".to_string()))?;

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    let asset: Asset = assets
        .filter(uuid.eq(asset_uuid))
        .filter(is_deleted.eq(false))
        .first::<Asset>(&mut conn)
        .await
        .map_err(|e| match e {
            diesel::result::Error::NotFound => AppError::NotFound("Asset not found".to_string()),
            _ => AppError::Database(e),
        })?;

    if asset.asset_type != AssetType::Ssh {
        return Err(AppError::Validation(
            "Host key status is only available for SSH assets".to_string(),
        ));
    }

    let host_key = asset
        .connection_config
        .get("ssh_host_key")
        .and_then(|v| v.as_str());
    let fingerprint = asset
        .connection_config
        .get("ssh_host_key_fingerprint")
        .and_then(|v| v.as_str());
    let is_mismatch = asset
        .connection_config
        .get("ssh_host_key_mismatch")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let response = match (host_key, fingerprint) {
        (Some(key), Some(fp)) => {
            let key_status = if is_mismatch { "mismatch" } else { "verified" };
            serde_json::json!({
                "status": key_status,
                "fingerprint": fp,
                "host_key": key,
            })
        }
        _ => serde_json::json!({
            "status": "no_key",
        }),
    };

    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    //! Source-level invariants on this admin-only API module.

    /// The admin "Manage Assets" API must NEVER expose a code path
    /// that can open a session. Forbidden tokens are built from
    /// `format!` so the test cannot match its own assertion strings.
    #[test]
    fn module_source_has_no_session_opening_path() {
        let source = include_str!("manage_assets.rs");
        let body = source
            .split("#[cfg(test)]")
            .next()
            .expect("module always has a non-test prefix");
        let stripped: String = body
            .lines()
            .map(|l| {
                let t = l.trim_start();
                if t.starts_with("//") {
                    ""
                } else {
                    l
                }
            })
            .collect::<Vec<_>>()
            .join("\n");

        let forbidden = [
            format!("connect{}rdp", "-"),
            format!("connect{}ssh", "_"),
            format!("submit{}access{}request", "_", "_"),
            format!("ws{}://", "s"),
            format!("Web{}Socket", ""),
        ];

        for pat in &forbidden {
            assert!(
                !stripped.contains(pat.as_str()),
                "api/manage_assets.rs (admin zone) must never reference '{}'",
                pat
            );
        }
    }

    /// Every public handler exported by this module MUST gate on
    /// `perms.assets_manage` in its first ~30 lines (defence-in-depth).
    #[test]
    fn every_public_handler_gates_on_assets_manage() {
        let source = include_str!("manage_assets.rs");
        let body = source
            .split("#[cfg(test)]")
            .next()
            .expect("module always has a non-test prefix");

        let gate_pattern = format!("perms.assets_{}", "manage");

        let mut cursor = 0usize;
        let needle = "pub async fn ";
        while let Some(pos) = body[cursor..].find(needle) {
            let absolute = cursor + pos;
            let slice_end = body[absolute..]
                .lines()
                .take(30)
                .map(|l| l.len() + 1)
                .sum::<usize>();
            let slice = &body[absolute..(absolute + slice_end).min(body.len())];

            let after_needle = &body[absolute + needle.len()..];
            let name: String = after_needle
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();

            assert!(
                slice.contains(gate_pattern.as_str()),
                "admin API handler `{name}` must gate on `{gate_pattern}` in its \
                 first ~30 lines (defence-in-depth even if the routing layer \
                 fails); not found in `api/manage_assets.rs`",
            );

            cursor = absolute + needle.len();
        }
    }
}
