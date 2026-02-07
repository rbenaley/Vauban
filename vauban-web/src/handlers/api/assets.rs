/// VAUBAN Web - Assets API handlers.
///
/// JSON API handlers for asset management.
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
use crate::error::{AppError, AppResult};
use crate::middleware::auth::AuthUser;
use crate::models::asset::{Asset, CreateAssetRequest, NewAsset, UpdateAssetRequest};
use crate::schema::assets::dsl::*;

/// Query parameters for list assets.
#[derive(Debug, Deserialize)]
pub struct ListAssetsParams {
    pub asset_type: Option<String>,
    pub group_id: Option<i32>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// List assets handler.
pub async fn list_assets(
    State(state): State<AppState>,
    _user: AuthUser,
    Query(params): Query<ListAssetsParams>,
) -> AppResult<Json<Vec<Asset>>> {
    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;
    let mut query = assets.filter(is_deleted.eq(false)).into_boxed();

    if let Some(asset_type_val) = params.asset_type {
        query = query.filter(asset_type.eq(asset_type_val));
    }

    if let Some(group_id_val) = params.group_id {
        query = query.filter(group_id.eq(Some(group_id_val)));
    }

    let assets_list = query
        .limit(params.limit.unwrap_or(50))
        .offset(params.offset.unwrap_or(0))
        .load::<Asset>(&mut conn)
        .await?;

    Ok(Json(assets_list))
}

/// Get asset by UUID handler.
pub async fn get_asset(
    State(state): State<AppState>,
    _user: AuthUser,
    Path(asset_uuid_str): Path<String>,
) -> AppResult<Json<Asset>> {
    // Parse UUID manually for better error messages
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

/// Create asset handler.
pub async fn create_asset(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<CreateAssetRequest>,
) -> AppResult<Json<Asset>> {
    super::require_staff(&user)?;

    validator::Validate::validate(&request)
        .map_err(|e| AppError::Validation(format!("Validation failed: {:?}", e)))?;

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    let asset_type_enum = crate::models::asset::AssetType::parse(&request.asset_type);
    let default_port = request.port.unwrap_or(asset_type_enum.default_port());

    // Validate and convert IP address format if provided
    let ip_addr_network = if let Some(ref ip_str) = request.ip_address {
        let ip_addr: std::net::IpAddr = ip_str
            .parse()
            .map_err(|_| AppError::Validation("Invalid IP address format".to_string()))?;
        Some(ipnetwork::IpNetwork::from(ip_addr))
    } else {
        None
    };

    // Sanitize text fields to prevent XSS (strip ALL HTML tags)
    let strip = |s: &str| -> String {
        ammonia::Builder::new()
            .tags(std::collections::HashSet::new())
            .clean(s)
            .to_string()
    };
    let sanitized_name = strip(&request.name);
    let sanitized_description = request.description.map(|d| strip(&d));

    let new_asset = NewAsset {
        uuid: Uuid::new_v4(),
        name: sanitized_name,
        hostname: request.hostname,
        ip_address: ip_addr_network,
        port: default_port,
        asset_type: request.asset_type,
        status: "unknown".to_string(),
        group_id: request.group_id,
        description: sanitized_description,
        os_type: None,
        os_version: None,
        connection_config: serde_json::json!({}),
        default_credential_id: None,
        require_mfa: request.require_mfa.unwrap_or(false),
        require_justification: request.require_justification.unwrap_or(false),
        max_session_duration: 28800, // 8 hours
        created_by_id: None,         // TODO: Get from user
    };

    let asset: Asset = diesel::insert_into(assets)
        .values(&new_asset)
        .get_result(&mut conn)
        .await?;

    Ok(Json(asset))
}

/// Update asset handler.
///
/// Supports HTMX requests by returning:
/// - HX-Redirect header on success (HTMX will redirect automatically)
/// - HTML error fragment on failure (for display in error container)
pub async fn update_asset(
    State(state): State<AppState>,
    user: AuthUser,
    headers: HeaderMap,
    Path(asset_uuid_str): Path<String>,
    Json(request): Json<UpdateAssetRequest>,
) -> Response {
    use crate::error::{htmx_error_response, is_htmx_request};

    if let Err(e) = super::require_staff(&user) {
        return e.into_response();
    }

    let is_htmx = is_htmx_request(&headers);

    // Helper macro to return appropriate error response
    macro_rules! handle_error {
        ($status:expr, $msg:expr) => {
            if is_htmx {
                return htmx_error_response($status, $msg).into_response();
            } else {
                return AppError::Validation($msg.to_string()).into_response();
            }
        };
    }

    // Parse UUID manually for better error messages
    let asset_uuid = match Uuid::parse_str(&asset_uuid_str) {
        Ok(parsed_uuid) => parsed_uuid,
        Err(_) => {
            handle_error!(StatusCode::BAD_REQUEST, "Invalid UUID format");
        }
    };

    // Validate request
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
        assets, description as description_col, hostname as hostname_col,
        ip_address as ip_address_col, name as name_col, port as port_col,
        require_justification as require_justification_col, require_mfa as require_mfa_col,
        status as status_col, updated_at, uuid,
    };
    use chrono::Utc;

    // First, get the existing asset
    let existing: Asset = match assets.filter(uuid.eq(asset_uuid)).first(&mut conn).await {
        Ok(a) => a,
        Err(_) => {
            handle_error!(StatusCode::NOT_FOUND, "Asset not found");
        }
    };

    // Parse ip_address if provided
    let new_ip_address = if let Some(ip_str) = &request.ip_address {
        match ip_str.parse() {
            Ok(ip) => Some(ip),
            Err(_) => {
                handle_error!(StatusCode::BAD_REQUEST, "Invalid IP address format");
            }
        }
    } else {
        None
    };

    // Sanitize text fields to prevent XSS (strip ALL HTML tags)
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

    // Build update with provided values or keep existing
    let asset: Asset = match diesel::update(assets.filter(uuid.eq(asset_uuid)))
        .set((
            name_col.eq(sanitized_name),
            hostname_col.eq(request.hostname.unwrap_or(existing.hostname)),
            ip_address_col.eq(new_ip_address.or(existing.ip_address)),
            port_col.eq(request.port.unwrap_or(existing.port)),
            status_col.eq(request.status.unwrap_or(existing.status)),
            description_col.eq(sanitized_description),
            require_mfa_col.eq(request.require_mfa.unwrap_or(existing.require_mfa)),
            require_justification_col.eq(request
                .require_justification
                .unwrap_or(existing.require_justification)),
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
        // Return empty body with HX-Redirect header for HTMX
        let mut response_headers = HeaderMap::new();
        // SAFETY: asset_uuid is a valid UUID which produces valid ASCII when formatted
        #[allow(clippy::expect_used)]
        let redirect_value = format!("/assets/{}", asset_uuid)
            .parse()
            .expect("UUID format produces valid header value");
        response_headers.insert("HX-Redirect", redirect_value);
        (response_headers, Json(asset)).into_response()
    } else {
        // Regular API response
        Json(asset).into_response()
    }
}

// =============================================================================
// Asset Groups API
// =============================================================================

use crate::models::asset::AssetGroup;

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

/// List asset groups handler.
pub async fn list_asset_groups(
    State(state): State<AppState>,
    _user: AuthUser,
    Query(params): Query<ListAssetGroupsParams>,
) -> AppResult<Json<Vec<AssetGroupResponse>>> {
    use crate::schema::asset_groups::dsl as ag;
    use crate::schema::assets::dsl as a;

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    // Get all non-deleted asset groups
    let groups: Vec<AssetGroup> = ag::asset_groups
        .filter(ag::is_deleted.eq(false))
        .order(ag::name.asc())
        .limit(params.limit.unwrap_or(100))
        .offset(params.offset.unwrap_or(0))
        .load(&mut conn)
        .await?;

    // Build response with asset counts
    let mut response: Vec<AssetGroupResponse> = Vec::with_capacity(groups.len());
    for group in groups {
        let asset_count: i64 = a::assets
            .filter(a::group_id.eq(group.id))
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
    pub ip_address: Option<String>,
    pub port: i32,
    pub asset_type: String,
    pub status: String,
    pub description: Option<String>,
    pub require_mfa: bool,
    pub require_justification: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// List assets in a specific asset group.
pub async fn list_group_assets(
    State(state): State<AppState>,
    _user: AuthUser,
    Path(group_uuid_str): Path<String>,
    Query(params): Query<ListAssetsParams>,
) -> AppResult<Json<Vec<GroupAssetResponse>>> {
    use crate::schema::asset_groups::dsl as ag;
    use crate::schema::assets::dsl as a;

    // Parse UUID manually for better error messages
    let group_uuid = Uuid::parse_str(&group_uuid_str)
        .map_err(|_| AppError::Validation("Invalid UUID format".to_string()))?;

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    // Get the group to verify it exists
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

    // Get assets in this group
    let group_assets: Vec<Asset> = a::assets
        .filter(a::group_id.eq(group.id))
        .filter(a::is_deleted.eq(false))
        .order(a::name.asc())
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
            ip_address: asset.ip_address.map(|ip| ip.ip().to_string()),
            port: asset.port,
            asset_type: asset.asset_type,
            status: asset.status,
            description: asset.description,
            require_mfa: asset.require_mfa,
            require_justification: asset.require_justification,
            created_at: asset.created_at,
            updated_at: asset.updated_at,
        })
        .collect();

    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_assets_params_defaults() {
        let params = ListAssetsParams {
            asset_type: None,
            group_id: None,
            limit: None,
            offset: None,
        };

        assert_eq!(params.limit.unwrap_or(50), 50);
        assert_eq!(params.offset.unwrap_or(0), 0);
    }
}
