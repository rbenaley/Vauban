/// VAUBAN Web - Session management handlers.

use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::Deserialize;
use ::uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::middleware::auth::AuthUser;
use crate::models::session::{CreateSessionRequest, ProxySession, NewProxySession};
use crate::schema::proxy_sessions::dsl::*;
use crate::AppState;
use crate::db::get_connection;
use diesel::prelude::*;

/// List sessions handler.
pub async fn list_sessions(
    State(state): State<AppState>,
    user: AuthUser,
    Query(params): Query<ListSessionsParams>,
) -> AppResult<Json<Vec<ProxySession>>> {
    let mut conn = get_connection(&state.db_pool)?;
    let mut query = proxy_sessions.into_boxed();

    // Filter by user if not admin
    // TODO: Check admin status
    if params.user_id.is_none() {
        use ::uuid::Uuid as UuidType;
        let _user_uuid: UuidType = UuidType::parse_str(&user.uuid).map_err(|_| {
            crate::error::AppError::Validation("Invalid user UUID".to_string())
        })?;
        // TODO: Join with users table to filter by UUID
    }

    let sessions_list = query
        .limit(params.limit.unwrap_or(50))
        .offset(params.offset.unwrap_or(0))
        .order(created_at.desc())
        .load::<ProxySession>(&mut conn)?;

    Ok(Json(sessions_list))
}

/// Get session by UUID handler.
pub async fn get_session(
    State(state): State<AppState>,
    _user: AuthUser,
    Path(session_uuid): Path<Uuid>,
) -> AppResult<Json<ProxySession>> {
    let mut conn = get_connection(&state.db_pool)?;
    let session = proxy_sessions
        .filter(uuid.eq(session_uuid))
        .first::<ProxySession>(&mut conn)
        .map_err(|e| match e {
            diesel::result::Error::NotFound => AppError::NotFound("Session not found".to_string()),
            _ => AppError::Database(e),
        })?;

    Ok(Json(session))
}

/// Create session handler.
pub async fn create_session(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<CreateSessionRequest>,
) -> AppResult<Json<ProxySession>> {
    validator::Validate::validate(&request).map_err(|e| {
        AppError::Validation(format!("Validation failed: {:?}", e))
    })?;

    let mut conn = get_connection(&state.db_pool)?;

    // TODO: Verify user has access to asset via RBAC
    // TODO: Get asset and credential details
    // TODO: Call proxy service to establish connection

    // TODO: Get real client IP from request headers
    let client_ip_network: ipnetwork::IpNetwork = "127.0.0.1".parse::<std::net::IpAddr>()
        .map(ipnetwork::IpNetwork::from)
        .unwrap();

    let new_session = NewProxySession {
        uuid: Uuid::new_v4(),
        user_id: 0, // TODO: Get from user UUID
        asset_id: 0, // TODO: Get from asset UUID
        credential_id: request.credential_id,
        credential_username: String::new(), // TODO: Get from vault
        session_type: request.session_type,
        status: "pending".to_string(),
        client_ip: client_ip_network,
        client_user_agent: None,
        proxy_instance: None,
        justification: request.justification,
        is_recorded: true,
        metadata: serde_json::json!({}),
    };

    let session: ProxySession = diesel::insert_into(proxy_sessions)
        .values(&new_session)
        .get_result(&mut conn)?;

    Ok(Json(session))
}

/// Query parameters for list sessions.
#[derive(Debug, Deserialize)]
pub struct ListSessionsParams {
    pub user_id: Option<String>,
    pub asset_id: Option<Uuid>,
    pub status: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

impl ListSessionsParams {
    /// Get limit with default value.
    pub fn get_limit(&self) -> i64 {
        self.limit.unwrap_or(50)
    }

    /// Get offset with default value.
    pub fn get_offset(&self) -> i64 {
        self.offset.unwrap_or(0)
    }

    /// Check if filtering by user.
    pub fn has_user_filter(&self) -> bool {
        self.user_id.is_some()
    }

    /// Check if filtering by asset.
    pub fn has_asset_filter(&self) -> bool {
        self.asset_id.is_some()
    }

    /// Check if filtering by status.
    pub fn has_status_filter(&self) -> bool {
        self.status.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::session::CreateSessionRequest;
    use validator::Validate;

    // ==================== ListSessionsParams Tests ====================

    #[test]
    fn test_list_sessions_params_default_limit() {
        let params = ListSessionsParams {
            user_id: None,
            asset_id: None,
            status: None,
            limit: None,
            offset: None,
        };

        assert_eq!(params.get_limit(), 50);
    }

    #[test]
    fn test_list_sessions_params_custom_limit() {
        let params = ListSessionsParams {
            user_id: None,
            asset_id: None,
            status: None,
            limit: Some(100),
            offset: None,
        };

        assert_eq!(params.get_limit(), 100);
    }

    #[test]
    fn test_list_sessions_params_default_offset() {
        let params = ListSessionsParams {
            user_id: None,
            asset_id: None,
            status: None,
            limit: None,
            offset: None,
        };

        assert_eq!(params.get_offset(), 0);
    }

    #[test]
    fn test_list_sessions_params_has_user_filter() {
        let params = ListSessionsParams {
            user_id: Some("user-123".to_string()),
            asset_id: None,
            status: None,
            limit: None,
            offset: None,
        };

        assert!(params.has_user_filter());
    }

    #[test]
    fn test_list_sessions_params_no_user_filter() {
        let params = ListSessionsParams {
            user_id: None,
            asset_id: None,
            status: None,
            limit: None,
            offset: None,
        };

        assert!(!params.has_user_filter());
    }

    #[test]
    fn test_list_sessions_params_has_asset_filter() {
        let params = ListSessionsParams {
            user_id: None,
            asset_id: Some(Uuid::new_v4()),
            status: None,
            limit: None,
            offset: None,
        };

        assert!(params.has_asset_filter());
    }

    #[test]
    fn test_list_sessions_params_has_status_filter() {
        let params = ListSessionsParams {
            user_id: None,
            asset_id: None,
            status: Some("active".to_string()),
            limit: None,
            offset: None,
        };

        assert!(params.has_status_filter());
    }

    #[test]
    fn test_list_sessions_params_all_filters() {
        let params = ListSessionsParams {
            user_id: Some("user-123".to_string()),
            asset_id: Some(Uuid::new_v4()),
            status: Some("active".to_string()),
            limit: Some(10),
            offset: Some(20),
        };

        assert!(params.has_user_filter());
        assert!(params.has_asset_filter());
        assert!(params.has_status_filter());
        assert_eq!(params.get_limit(), 10);
        assert_eq!(params.get_offset(), 20);
    }

    // ==================== CreateSessionRequest Validation Tests ====================

    #[test]
    fn test_create_session_request_valid() {
        let request = CreateSessionRequest {
            asset_id: Uuid::new_v4(),
            credential_id: "cred-123".to_string(),
            session_type: "ssh".to_string(),
            justification: Some("Maintenance task".to_string()),
        };

        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_create_session_request_without_justification() {
        let request = CreateSessionRequest {
            asset_id: Uuid::new_v4(),
            credential_id: "cred-456".to_string(),
            session_type: "rdp".to_string(),
            justification: None,
        };

        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_create_session_request_different_session_types() {
        let session_types = ["ssh", "rdp", "vnc"];

        for st in session_types {
            let request = CreateSessionRequest {
                asset_id: Uuid::new_v4(),
                credential_id: "cred".to_string(),
                session_type: st.to_string(),
                justification: None,
            };

            assert!(request.validate().is_ok());
        }
    }
}

