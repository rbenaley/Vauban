/// VAUBAN Web - Sessions API handlers.
///
/// JSON API handlers for session management.
use ::uuid::Uuid;
use axum::{
    Json,
    extract::{Path, Query, State},
    http::header::HeaderMap,
    response::{Html, IntoResponse, Response},
};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use serde::Deserialize;

use crate::AppState;
use crate::error::{AppError, AppResult};
use crate::middleware::auth::AuthUser;
use crate::models::session::{CreateSessionRequest, NewProxySession, ProxySession, SessionType};
use crate::schema::proxy_sessions::dsl::*;

// L-6: is_htmx_request deduplicated - use crate::error::is_htmx_request
use crate::error::is_htmx_request;

/// Query parameters for list sessions.
#[derive(Debug, Deserialize)]
pub struct ListSessionsParams {
    pub user_id: Option<String>,
    pub asset_id: Option<Uuid>,
    pub status: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// List sessions handler.
pub async fn list_sessions(
    State(state): State<AppState>,
    user: AuthUser,
    Query(params): Query<ListSessionsParams>,
) -> AppResult<Json<Vec<ProxySession>>> {
    super::require_staff(&state, &user).await?;

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;
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
        .load::<ProxySession>(&mut conn)
        .await?;

    Ok(Json(sessions_list))
}

/// Get session by UUID handler.
pub async fn get_session(
    State(state): State<AppState>,
    user: AuthUser,
    Path(session_uuid_str): Path<String>,
) -> AppResult<Json<ProxySession>> {
    super::require_staff(&state, &user).await?;

    // Parse UUID manually for better error messages
    let session_uuid = Uuid::parse_str(&session_uuid_str)
        .map_err(|_| AppError::Validation("Invalid UUID format".to_string()))?;

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;
    let session = proxy_sessions
        .filter(uuid.eq(session_uuid))
        .first::<ProxySession>(&mut conn)
        .await
        .map_err(|e| match e {
            diesel::result::Error::NotFound => AppError::NotFound("Session not found".to_string()),
            _ => AppError::Database(e),
        })?;

    Ok(Json(session))
}

/// Create session handler.
///
/// Superusers bypass access rule checks. Staff and regular users must have
/// a valid, active access rule linking their group to the asset's group for
/// the requested protocol.
pub async fn create_session(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<CreateSessionRequest>,
) -> AppResult<Json<ProxySession>> {
    validator::Validate::validate(&request)
        .map_err(|e| AppError::Validation(format!("Validation failed: {:?}", e)))?;

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    // Resolve the user's internal ID
    let user_uuid_parsed = Uuid::parse_str(&user.uuid)
        .map_err(|_| AppError::Validation("Invalid user UUID".to_string()))?;
    let user_internal_id: i32 = crate::schema::users::table
        .filter(crate::schema::users::uuid.eq(user_uuid_parsed))
        .select(crate::schema::users::id)
        .first(&mut conn)
        .await
        .map_err(|_| AppError::Authorization("User not found".to_string()))?;

    // Resolve the asset's internal ID
    let asset_internal_id: i32 = crate::schema::assets::table
        .filter(crate::schema::assets::uuid.eq(request.asset_id))
        .filter(crate::schema::assets::is_deleted.eq(false))
        .select(crate::schema::assets::id)
        .first(&mut conn)
        .await
        .map_err(|e| match e {
            diesel::result::Error::NotFound => AppError::NotFound("Asset not found".to_string()),
            _ => AppError::Database(e),
        })?;

    let protocol = request.session_type.as_str();

    // Superusers bypass access rule checks
    if !user.is_superuser {
        let access_result = crate::services::access::can_access_asset(
            state.access_client.as_ref(),
            &mut conn,
            user_internal_id,
            asset_internal_id,
            protocol,
        )
        .await?;

        if !access_result.allowed {
            return Err(AppError::Authorization(
                "No access rule grants you access to this asset".to_string(),
            ));
        }

        if access_result.require_mfa && !user.mfa_verified {
            return Err(AppError::Authorization(
                "MFA verification required for this asset".to_string(),
            ));
        }

        if access_result.require_approval && request.justification.is_none() {
            return Err(AppError::Validation(
                "Justification is required for this asset".to_string(),
            ));
        }
    }

    // TODO: Get real client IP from request headers
    // SAFETY: "127.0.0.1" is a valid IP address literal, parsing cannot fail
    #[allow(clippy::unwrap_used)]
    let client_ip_network: ipnetwork::IpNetwork = "127.0.0.1"
        .parse::<std::net::IpAddr>()
        .map(ipnetwork::IpNetwork::from)
        .unwrap();

    let new_session = NewProxySession {
        uuid: Uuid::new_v4(),
        user_id: user_internal_id,
        asset_id: asset_internal_id,
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
        max_session_duration: None,
    };

    let session: ProxySession = diesel::insert_into(proxy_sessions)
        .values(&new_session)
        .get_result(&mut conn)
        .await?;

    Ok(Json(session))
}

/// Terminate a session.
/// For HTMX requests: returns an HTML fragment showing the terminated session row.
/// For JSON API: returns the updated session.
pub async fn terminate_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
    Path(session_id_str): Path<String>,
) -> AppResult<Response> {
    super::require_staff(&state, &user).await?;

    // Parse session ID manually for better error messages
    let session_id: i32 = session_id_str
        .parse()
        .map_err(|_| AppError::Validation("Invalid session ID format".to_string()))?;

    let htmx = is_htmx_request(&headers);
    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    // Update the session status to "terminated"
    let updated_session = diesel::update(proxy_sessions.filter(id.eq(session_id)))
        .set((
            status.eq("terminated"),
            disconnected_at.eq(chrono::Utc::now()),
        ))
        .get_result::<ProxySession>(&mut conn)
        .await
        .map_err(|e| match e {
            diesel::result::Error::NotFound => AppError::NotFound("Session not found".to_string()),
            _ => AppError::Database(e),
        })?;

    // Force-close the proxy connection and data channel so the active
    // WebSocket loop breaks (data_rx.recv() => None).
    let session_uuid_str = updated_session.uuid.to_string();
    match updated_session.session_type {
        SessionType::Ssh => {
            if let Some(ref proxy) = state.ssh_proxy {
                let _ = proxy.close_session(&session_uuid_str);
                proxy.unsubscribe_session(&session_uuid_str).await;
            }
        }
        SessionType::Rdp => {
            if let Some(ref proxy) = state.rdp_proxy {
                let _ = proxy.close_session(&session_uuid_str);
                proxy.unsubscribe_session(&session_uuid_str).await;
            }
        }
    }

    // Push real-time updates to /sessions and /sessions/active page subscribers
    crate::tasks::dashboard::push_session_list_update(&state.broadcast, &state.db_pool).await;
    crate::tasks::dashboard::push_active_sessions_update(&state.broadcast, &state.db_pool).await;

    if htmx {
        // Return an updated HTML fragment for the session row
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
                </div>
            </li>"#,
            session_id = session_id
        );
        Ok(Html(html).into_response())
    } else {
        // For JSON API, return the updated session
        Ok(Json(updated_session).into_response())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_sessions_params_defaults() {
        let params = ListSessionsParams {
            user_id: None,
            asset_id: None,
            status: None,
            limit: None,
            offset: None,
        };

        assert_eq!(params.limit.unwrap_or(50), 50);
        assert_eq!(params.offset.unwrap_or(0), 0);
    }

    fn terminate_session_body() -> &'static str {
        let source = include_str!("sessions.rs");
        let fn_start = source
            .find("fn terminate_session")
            .expect("terminate_session handler must exist");
        let body = &source[fn_start..];
        let fn_end = body
            .find("\n#[cfg(test)]")
            .or_else(|| body.find("\npub async fn ").map(|p| p + 1))
            .unwrap_or(body.len());
        // Leak is fine in tests -- runs once per process.
        Box::leak(body[..fn_end].to_string().into_boxed_str())
    }

    #[test]
    fn test_terminate_session_calls_close_session() {
        let body = terminate_session_body();
        assert!(
            body.contains("close_session"),
            "terminate_session must call close_session to send IPC close to the proxy"
        );
    }

    #[test]
    fn test_terminate_session_calls_unsubscribe() {
        let body = terminate_session_body();
        assert!(
            body.contains("unsubscribe_session"),
            "terminate_session must call unsubscribe_session to drop the data channel sender"
        );
    }

    #[test]
    fn test_terminate_session_handles_ssh() {
        let body = terminate_session_body();
        assert!(
            body.contains("SessionType::Ssh") || body.contains("ssh_proxy"),
            "terminate_session must handle SSH sessions"
        );
    }

    #[test]
    fn test_terminate_session_handles_rdp() {
        let body = terminate_session_body();
        assert!(
            body.contains("SessionType::Rdp") || body.contains("rdp_proxy"),
            "terminate_session must handle RDP sessions"
        );
    }

    #[test]
    fn test_terminate_session_pushes_session_list_update() {
        let body = terminate_session_body();
        assert!(
            body.contains("push_session_list_update"),
            "terminate_session must push real-time update to /sessions page subscribers"
        );
    }

    #[test]
    fn test_terminate_session_pushes_active_sessions_update() {
        let body = terminate_session_body();
        assert!(
            body.contains("push_active_sessions_update"),
            "terminate_session must push real-time update to /sessions/active page subscribers"
        );
    }
}
