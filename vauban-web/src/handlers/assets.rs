/// VAUBAN Web - Asset management handlers.

use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::Deserialize;
use ::uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::middleware::auth::AuthUser;
use crate::models::asset::{Asset, CreateAssetRequest, UpdateAssetRequest, NewAsset};
use crate::schema::assets::dsl::*;
use crate::AppState;
use crate::db::get_connection;
use diesel::prelude::*;

/// List assets handler.
pub async fn list_assets(
    State(state): State<AppState>,
    _user: AuthUser,
    Query(params): Query<ListAssetsParams>,
) -> AppResult<Json<Vec<Asset>>> {
    let mut conn = get_connection(&state.db_pool)?;
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
        .load::<Asset>(&mut conn)?;

    Ok(Json(assets_list))
}

/// Get asset by UUID handler.
pub async fn get_asset(
    State(state): State<AppState>,
    _user: AuthUser,
    Path(asset_uuid): Path<Uuid>,
) -> AppResult<Json<Asset>> {
    let mut conn = get_connection(&state.db_pool)?;
    let asset = assets
        .filter(uuid.eq(asset_uuid))
        .filter(is_deleted.eq(false))
        .first::<Asset>(&mut conn)?;

    Ok(Json(asset))
}

/// Create asset handler.
pub async fn create_asset(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<CreateAssetRequest>,
) -> AppResult<Json<Asset>> {
    validator::Validate::validate(&request).map_err(|e| {
        AppError::Validation(format!("Validation failed: {:?}", e))
    })?;

    let mut conn = get_connection(&state.db_pool)?;

    let asset_type_enum = crate::models::asset::AssetType::from_str(&request.asset_type);
    let default_port = request.port.unwrap_or(asset_type_enum.default_port());
    
    // Validate IP address format if provided
    if let Some(ref ip_str) = request.ip_address {
        ip_str.parse::<std::net::IpAddr>().map_err(|_| {
            AppError::Validation("Invalid IP address format".to_string())
        })?;
    }

    let new_asset = NewAsset {
        uuid: Uuid::new_v4(),
        name: request.name,
        hostname: request.hostname,
        ip_address: request.ip_address,
        port: default_port,
        asset_type: request.asset_type,
        status: "unknown".to_string(),
        group_id: request.group_id,
        description: request.description,
        os_type: None,
        os_version: None,
        connection_config: serde_json::json!({}),
        default_credential_id: None,
        require_mfa: request.require_mfa.unwrap_or(false),
        require_justification: request.require_justification.unwrap_or(false),
        max_session_duration: 28800, // 8 hours
        created_by_id: None, // TODO: Get from user
    };

    let asset: Asset = diesel::insert_into(assets)
        .values(&new_asset)
        .get_result(&mut conn)?;

    Ok(Json(asset))
}

/// Update asset handler.
pub async fn update_asset(
    State(state): State<AppState>,
    _user: AuthUser,
    Path(asset_uuid): Path<Uuid>,
    Json(request): Json<UpdateAssetRequest>,
) -> AppResult<Json<Asset>> {
    validator::Validate::validate(&request).map_err(|e| {
        AppError::Validation(format!("Validation failed: {:?}", e))
    })?;

    let mut conn = get_connection(&state.db_pool)?;

    use crate::schema::assets::dsl::{assets, uuid, name as name_col, hostname as hostname_col, port as port_col, status as status_col, updated_at};
    use chrono::Utc;
    
    // First, get the existing asset
    let existing: Asset = assets.filter(uuid.eq(asset_uuid))
        .first(&mut conn)
        .map_err(|_| AppError::NotFound("Asset not found".to_string()))?;
    
    // Build update with provided values or keep existing
    let asset: Asset = diesel::update(assets.filter(uuid.eq(asset_uuid)))
        .set((
            name_col.eq(request.name.unwrap_or(existing.name)),
            hostname_col.eq(request.hostname.unwrap_or(existing.hostname)),
            port_col.eq(request.port.unwrap_or(existing.port)),
            status_col.eq(request.status.unwrap_or(existing.status)),
            updated_at.eq(Utc::now()),
        ))
        .get_result(&mut conn)?;

    Ok(Json(asset))
}

/// Query parameters for list assets.
#[derive(Debug, Deserialize)]
pub struct ListAssetsParams {
    pub asset_type: Option<String>,
    pub group_id: Option<i32>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

