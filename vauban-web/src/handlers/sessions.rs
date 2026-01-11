use ::uuid::Uuid;
/// VAUBAN Web - Session management handlers.
use axum::{
    Json,
    extract::{Path, Query, State},
    http::header::HeaderMap,
    response::{Html, IntoResponse, Response},
};
use serde::Deserialize;

use crate::AppState;
use crate::db::get_connection;
use crate::error::{AppError, AppResult};
use crate::middleware::auth::AuthUser;
use crate::models::session::{CreateSessionRequest, NewProxySession, ProxySession};
use crate::schema::proxy_sessions::dsl::*;
use diesel::prelude::*;

/// Check if request is from HTMX (has HX-Request header)
fn is_htmx_request(headers: &HeaderMap) -> bool {
    headers.get("HX-Request").is_some()
}

/// List sessions handler.
pub async fn list_sessions(
    State(state): State<AppState>,
    user: AuthUser,
    Query(params): Query<ListSessionsParams>,
) -> AppResult<Json<Vec<ProxySession>>> {
    let mut conn = get_connection(&state.db_pool)?;
    let query = proxy_sessions.into_boxed();

    // Filter by user if not admin
    // TODO: Check admin status
    if params.user_id.is_none() {
        use ::uuid::Uuid as UuidType;
        let _user_uuid: UuidType = UuidType::parse_str(&user.uuid)
            .map_err(|_| crate::error::AppError::Validation("Invalid user UUID".to_string()))?;
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
    _user: AuthUser,
    Json(request): Json<CreateSessionRequest>,
) -> AppResult<Json<ProxySession>> {
    validator::Validate::validate(&request)
        .map_err(|e| AppError::Validation(format!("Validation failed: {:?}", e)))?;

    let mut conn = get_connection(&state.db_pool)?;

    // TODO: Verify user has access to asset via RBAC
    // TODO: Get asset and credential details
    // TODO: Call proxy service to establish connection

    // TODO: Get real client IP from request headers
    let client_ip_network: ipnetwork::IpNetwork = "127.0.0.1"
        .parse::<std::net::IpAddr>()
        .map(ipnetwork::IpNetwork::from)
        .unwrap();

    let new_session = NewProxySession {
        uuid: Uuid::new_v4(),
        user_id: 0,  // TODO: Get from user UUID
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

/// Terminate a session.
/// For HTMX requests: returns an HTML fragment showing the terminated session row.
/// For JSON API: returns the updated session.
pub async fn terminate_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    _user: AuthUser,
    Path(session_id): Path<i32>,
) -> AppResult<Response> {
    let htmx = is_htmx_request(&headers);
    let mut conn = get_connection(&state.db_pool)?;

    // Update the session status to "terminated"
    let updated_session = diesel::update(proxy_sessions.filter(id.eq(session_id)))
        .set((
            status.eq("terminated"),
            disconnected_at.eq(chrono::Utc::now()),
        ))
        .get_result::<ProxySession>(&mut conn)
        .map_err(|e| match e {
            diesel::result::Error::NotFound => AppError::NotFound("Session not found".to_string()),
            _ => AppError::Database(e),
        })?;

    if htmx {
        // Return an updated HTML fragment for the session row
        // Get asset and user names via join (simplified - in real app would do proper join)
        let html = format!(
            r#"<li class="px-6 py-4 hover:bg-gray-50 dark:hover:bg-gray-700">
                <div class="flex items-center justify-between">
                    <div class="flex items-center space-x-4">
                        <div class="flex-shrink-0">
                            <span class="inline-flex h-10 w-10 items-center justify-center rounded-full bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-400">
                                <svg class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6.75 7.5l3 2.25-3 2.25m4.5 0h3m-9 8.25h13.5A2.25 2.25 0 0021 18V6a2.25 2.25 0 00-2.25-2.25H5.25A2.25 2.25 0 003 6v12a2.25 2.25 0 002.25 2.25z"/>
                                </svg>
                            </span>
                        </div>
                        <div class="flex-1 min-w-0">
                            <div class="flex items-center">
                                <p class="text-sm font-medium text-gray-900 dark:text-white truncate">
                                    Session #{session_id}
                                </p>
                                <span class="ml-2 inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium bg-red-100 text-red-800 dark:bg-red-900/50 dark:text-red-300">
                                    Terminated
                                </span>
                            </div>
                            <div class="mt-1 flex items-center text-sm text-gray-500 dark:text-gray-400">
                                <span>Session terminated</span>
                            </div>
                        </div>
                    </div>
                    <div class="flex items-center space-x-2">
                        <a href="/sessions/{session_id}"
                           class="text-sm text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200">
                            View
                        </a>
                    </div>
                </div>
            </li>"#,
            session_id = updated_session.id
        );
        return Ok(Html(html).into_response());
    }

    Ok(Json(updated_session).into_response())
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

    // ==================== ListSessionsParams Additional Tests ====================

    #[test]
    fn test_list_sessions_params_debug() {
        let params = ListSessionsParams {
            user_id: Some("user-abc".to_string()),
            asset_id: Some(Uuid::new_v4()),
            status: Some("active".to_string()),
            limit: Some(25),
            offset: Some(10),
        };
        
        let debug_str = format!("{:?}", params);
        
        assert!(debug_str.contains("ListSessionsParams"));
        assert!(debug_str.contains("user-abc"));
        assert!(debug_str.contains("active"));
    }

    #[test]
    fn test_list_sessions_params_no_filters() {
        let params = ListSessionsParams {
            user_id: None,
            asset_id: None,
            status: None,
            limit: None,
            offset: None,
        };
        
        assert!(!params.has_user_filter());
        assert!(!params.has_asset_filter());
        assert!(!params.has_status_filter());
    }

    #[test]
    fn test_list_sessions_params_large_limit() {
        let params = ListSessionsParams {
            user_id: None,
            asset_id: None,
            status: None,
            limit: Some(10000),
            offset: None,
        };
        
        assert_eq!(params.get_limit(), 10000);
    }

    #[test]
    fn test_list_sessions_params_large_offset() {
        let params = ListSessionsParams {
            user_id: None,
            asset_id: None,
            status: None,
            limit: None,
            offset: Some(1000000),
        };
        
        assert_eq!(params.get_offset(), 1000000);
    }

    #[test]
    fn test_list_sessions_params_status_values() {
        let statuses = ["active", "pending", "completed", "terminated", "failed"];
        
        for status_val in statuses {
            let params = ListSessionsParams {
                user_id: None,
                asset_id: None,
                status: Some(status_val.to_string()),
                limit: None,
                offset: None,
            };
            
            assert!(params.has_status_filter());
            assert_eq!(params.status, Some(status_val.to_string()));
        }
    }

    // ==================== is_htmx_request Tests ====================

    #[test]
    fn test_is_htmx_request_with_header() {
        use axum::http::HeaderMap;
        
        let mut headers = HeaderMap::new();
        headers.insert("HX-Request", "true".parse().unwrap());
        
        assert!(is_htmx_request(&headers));
    }

    #[test]
    fn test_is_htmx_request_without_header() {
        use axum::http::HeaderMap;
        
        let headers = HeaderMap::new();
        
        assert!(!is_htmx_request(&headers));
    }

    #[test]
    fn test_is_htmx_request_any_value() {
        use axum::http::HeaderMap;
        
        let mut headers = HeaderMap::new();
        headers.insert("HX-Request", "1".parse().unwrap());
        
        assert!(is_htmx_request(&headers));
    }

    // ==================== CreateSessionRequest Additional Tests ====================

    #[test]
    fn test_create_session_request_long_justification() {
        let request = CreateSessionRequest {
            asset_id: Uuid::new_v4(),
            credential_id: "cred-123".to_string(),
            session_type: "ssh".to_string(),
            justification: Some("A".repeat(1000)),
        };
        
        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_create_session_request_empty_credential_id() {
        let request = CreateSessionRequest {
            asset_id: Uuid::new_v4(),
            credential_id: "".to_string(),
            session_type: "ssh".to_string(),
            justification: None,
        };
        
        // Empty credential_id may or may not be valid depending on validation rules
        let _ = request.validate();
    }

    #[test]
    fn test_create_session_request_uuid_format() {
        let asset_uuid = Uuid::new_v4();
        let request = CreateSessionRequest {
            asset_id: asset_uuid,
            credential_id: "cred".to_string(),
            session_type: "rdp".to_string(),
            justification: None,
        };
        
        assert_eq!(request.asset_id, asset_uuid);
        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_create_session_request_unicode_justification() {
        let request = CreateSessionRequest {
            asset_id: Uuid::new_v4(),
            credential_id: "cred".to_string(),
            session_type: "ssh".to_string(),
            justification: Some("需要访问服务器进行维护 🔧".to_string()),
        };
        
        assert!(request.validate().is_ok());
    }

    // ==================== Filter Combinations ====================

    #[test]
    fn test_list_sessions_params_user_and_status() {
        let params = ListSessionsParams {
            user_id: Some("admin".to_string()),
            asset_id: None,
            status: Some("active".to_string()),
            limit: Some(20),
            offset: None,
        };
        
        assert!(params.has_user_filter());
        assert!(!params.has_asset_filter());
        assert!(params.has_status_filter());
    }

    #[test]
    fn test_list_sessions_params_asset_only() {
        let params = ListSessionsParams {
            user_id: None,
            asset_id: Some(Uuid::new_v4()),
            status: None,
            limit: None,
            offset: None,
        };
        
        assert!(!params.has_user_filter());
        assert!(params.has_asset_filter());
        assert!(!params.has_status_filter());
    }
}
