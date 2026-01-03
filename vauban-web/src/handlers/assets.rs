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
        .first::<Asset>(&mut conn)
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
    validator::Validate::validate(&request).map_err(|e| {
        AppError::Validation(format!("Validation failed: {:?}", e))
    })?;

    let mut conn = get_connection(&state.db_pool)?;

    let asset_type_enum = crate::models::asset::AssetType::from_str(&request.asset_type);
    let default_port = request.port.unwrap_or(asset_type_enum.default_port());
    
    // Validate and convert IP address format if provided
    let ip_addr_network = if let Some(ref ip_str) = request.ip_address {
        let ip_addr: std::net::IpAddr = ip_str.parse().map_err(|_| {
            AppError::Validation("Invalid IP address format".to_string())
        })?;
        Some(ipnetwork::IpNetwork::from(ip_addr))
    } else {
        None
    };

    let new_asset = NewAsset {
        uuid: Uuid::new_v4(),
        name: request.name,
        hostname: request.hostname,
        ip_address: ip_addr_network,
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

impl ListAssetsParams {
    /// Get limit with default value.
    pub fn get_limit(&self) -> i64 {
        self.limit.unwrap_or(50)
    }

    /// Get offset with default value.
    pub fn get_offset(&self) -> i64 {
        self.offset.unwrap_or(0)
    }
}

/// Validate IP address format.
pub fn validate_ip_address(ip_str: &str) -> Result<std::net::IpAddr, AppError> {
    ip_str.parse().map_err(|_| {
        AppError::Validation("Invalid IP address format".to_string())
    })
}

/// Convert IP address to IpNetwork.
pub fn ip_to_network(ip_addr: std::net::IpAddr) -> ipnetwork::IpNetwork {
    ipnetwork::IpNetwork::from(ip_addr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::asset::{CreateAssetRequest, UpdateAssetRequest};
    use validator::Validate;

    // ==================== ListAssetsParams Tests ====================

    #[test]
    fn test_list_assets_params_default_limit() {
        let params = ListAssetsParams {
            asset_type: None,
            group_id: None,
            limit: None,
            offset: None,
        };

        assert_eq!(params.get_limit(), 50);
    }

    #[test]
    fn test_list_assets_params_custom_limit() {
        let params = ListAssetsParams {
            asset_type: None,
            group_id: None,
            limit: Some(25),
            offset: None,
        };

        assert_eq!(params.get_limit(), 25);
    }

    #[test]
    fn test_list_assets_params_default_offset() {
        let params = ListAssetsParams {
            asset_type: None,
            group_id: None,
            limit: None,
            offset: None,
        };

        assert_eq!(params.get_offset(), 0);
    }

    #[test]
    fn test_list_assets_params_with_filters() {
        let params = ListAssetsParams {
            asset_type: Some("ssh".to_string()),
            group_id: Some(1),
            limit: Some(10),
            offset: Some(20),
        };

        assert_eq!(params.asset_type, Some("ssh".to_string()));
        assert_eq!(params.group_id, Some(1));
        assert_eq!(params.get_limit(), 10);
        assert_eq!(params.get_offset(), 20);
    }

    // ==================== IP Address Validation Tests ====================

    #[test]
    fn test_validate_ip_address_valid_ipv4() {
        let result = validate_ip_address("192.168.1.1");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_ip_address_valid_ipv6() {
        let result = validate_ip_address("::1");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_ip_address_valid_ipv6_full() {
        let result = validate_ip_address("2001:0db8:85a3:0000:0000:8a2e:0370:7334");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_ip_address_invalid() {
        let result = validate_ip_address("not-an-ip");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_ip_address_invalid_format() {
        let result = validate_ip_address("256.1.1.1");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_ip_address_empty() {
        let result = validate_ip_address("");
        assert!(result.is_err());
    }

    // ==================== IP to Network Tests ====================

    #[test]
    fn test_ip_to_network_ipv4() {
        let ip: std::net::IpAddr = "192.168.1.100".parse().unwrap();
        let network = ip_to_network(ip);

        assert_eq!(network.ip(), ip);
    }

    #[test]
    fn test_ip_to_network_ipv6() {
        let ip: std::net::IpAddr = "::1".parse().unwrap();
        let network = ip_to_network(ip);

        assert_eq!(network.ip(), ip);
    }

    // ==================== CreateAssetRequest Validation Tests ====================

    #[test]
    fn test_create_asset_request_valid() {
        let request = CreateAssetRequest {
            name: "My Server".to_string(),
            hostname: "server.example.com".to_string(),
            ip_address: Some("192.168.1.1".to_string()),
            port: Some(22),
            asset_type: "ssh".to_string(),
            group_id: None,
            description: None,
            require_mfa: None,
            require_justification: None,
        };

        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_create_asset_request_empty_name() {
        let request = CreateAssetRequest {
            name: "".to_string(),
            hostname: "server.example.com".to_string(),
            ip_address: None,
            port: None,
            asset_type: "ssh".to_string(),
            group_id: None,
            description: None,
            require_mfa: None,
            require_justification: None,
        };

        assert!(request.validate().is_err());
    }

    #[test]
    fn test_create_asset_request_invalid_port() {
        let request = CreateAssetRequest {
            name: "My Server".to_string(),
            hostname: "server.example.com".to_string(),
            ip_address: None,
            port: Some(70000), // Invalid port
            asset_type: "ssh".to_string(),
            group_id: None,
            description: None,
            require_mfa: None,
            require_justification: None,
        };

        assert!(request.validate().is_err());
    }

    // ==================== UpdateAssetRequest Validation Tests ====================

    #[test]
    fn test_update_asset_request_valid() {
        let request = UpdateAssetRequest {
            name: Some("Updated Server".to_string()),
            hostname: Some("new.example.com".to_string()),
            ip_address: None,
            port: Some(2222),
            status: Some("online".to_string()),
            description: Some("Updated description".to_string()),
            require_mfa: None,
            require_justification: None,
        };

        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_update_asset_request_empty() {
        let request = UpdateAssetRequest {
            name: None,
            hostname: None,
            ip_address: None,
            port: None,
            status: None,
            description: None,
            require_mfa: None,
            require_justification: None,
        };

        // Empty update should be valid
        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_update_asset_request_invalid_port() {
        let request = UpdateAssetRequest {
            name: None,
            hostname: None,
            ip_address: None,
            port: Some(0), // Invalid port
            status: None,
            description: None,
            require_mfa: None,
            require_justification: None,
        };

        assert!(request.validate().is_err());
    }
}

