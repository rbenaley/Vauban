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
        .first::<ProxySession>(&mut conn)?;

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
    let client_ip_val = "127.0.0.1".to_string();

    let new_session = NewProxySession {
        uuid: Uuid::new_v4(),
        user_id: 0, // TODO: Get from user UUID
        asset_id: 0, // TODO: Get from asset UUID
        credential_id: request.credential_id,
        credential_username: String::new(), // TODO: Get from vault
        session_type: request.session_type,
        status: "pending".to_string(),
        client_ip: client_ip_val,
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

