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
use crate::auth::PermissionContext;
use crate::error::{AppError, AppResult};
use crate::middleware::auth::AuthUser;
use crate::models::session::{CreateSessionRequest, NewProxySession, ProxySession};
use crate::schema::proxy_sessions::dsl::*;

// is_htmx_request deduplicated - use crate::error::is_htmx_request
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
///
/// SECURITY: layered authorisation:
/// 1. functional `sessions:read` (Casbin) -- can read sessions at all.
/// 2. instance-level visibility:
///    - WITHOUT `sessions:supervise`, the result set is force-filtered
///      to `user_id == caller`. The optional `user_id` param is
///      ignored (or, if it points to someone else, replaced with the
///      caller). Without this layer, every regular API consumer that
///      held `sessions:read` could enumerate every session of every
///      user.
///    - WITH `sessions:supervise`, the caller can pass any `user_id`,
///      `asset_id` or `status` filter and observe the matching
///      cross-user view -- this is the supervisor / auditor seat.
/// 3. `asset_id` and `status` filters are honoured for both classes
///    of caller; they only narrow what is visible, never widen it.
pub async fn list_sessions(
    State(state): State<AppState>,
    user: AuthUser,
    perms: PermissionContext,
    Query(params): Query<ListSessionsParams>,
) -> AppResult<Json<Vec<ProxySession>>> {
    use crate::schema::users;

    if !perms.sessions_read {
        return Err(AppError::forbidden("sessions:read"));
    }

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    let caller_uuid = Uuid::parse_str(&user.uuid)
        .map_err(|_| AppError::Internal(anyhow::anyhow!("invalid caller uuid")))?;
    let caller_id: i32 = users::table
        .filter(users::uuid.eq(caller_uuid))
        .select(users::id)
        .first(&mut conn)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("caller lookup failed: {}", e)))?;

    // Resolve the optional user_id filter (UUID string) to an i32.
    // Unknown UUID -> empty result for both classes (a probe cannot
    // tell "no sessions" from "no such user").
    let requested_user_id: Option<i32> = if let Some(ref uid_str) = params.user_id {
        let uid = Uuid::parse_str(uid_str)
            .map_err(|_| AppError::Validation("Invalid user_id UUID".to_string()))?;
        match users::table
            .filter(users::uuid.eq(uid))
            .select(users::id)
            .first::<i32>(&mut conn)
            .await
        {
            Ok(uid_i32) => Some(uid_i32),
            Err(diesel::result::Error::NotFound) => return Ok(Json(Vec::new())),
            Err(e) => return Err(AppError::Database(e)),
        }
    } else {
        None
    };

    // Resolve optional asset_id (UUID -> i32). Unknown UUID -> empty.
    let requested_asset_id: Option<i32> = if let Some(asset_uuid_param) = params.asset_id {
        use crate::schema::assets as schema_assets;
        match schema_assets::table
            .filter(schema_assets::uuid.eq(asset_uuid_param))
            .select(schema_assets::id)
            .first::<i32>(&mut conn)
            .await
        {
            Ok(aid_i32) => Some(aid_i32),
            Err(diesel::result::Error::NotFound) => return Ok(Json(Vec::new())),
            Err(e) => return Err(AppError::Database(e)),
        }
    } else {
        None
    };

    // Effective user_id filter:
    // - supervise: honour `requested_user_id` as-is (None == every
    //   user).
    // - non-supervise: ALWAYS force `caller_id`, regardless of what
    //   the param said. A regular user that asks for `user_id=other`
    //   gets the same response shape as if they asked nothing.
    let effective_user_id: i32 = if perms.sessions_supervise {
        requested_user_id.unwrap_or(caller_id)
    } else {
        caller_id
    };
    let force_caller_only = !perms.sessions_supervise;

    let mut q = proxy_sessions.into_boxed();
    if force_caller_only || requested_user_id.is_some() {
        q = q.filter(user_id.eq(effective_user_id));
    }
    if let Some(aid) = requested_asset_id {
        q = q.filter(asset_id.eq(aid));
    }
    if let Some(ref s) = params.status {
        q = q.filter(status.eq(s));
    }

    let sessions_list = q
        .limit(params.limit.unwrap_or(50))
        .offset(params.offset.unwrap_or(0))
        .order(created_at.desc())
        .load::<ProxySession>(&mut conn)
        .await?;

    Ok(Json(sessions_list))
}

/// Get session by UUID handler.
///
/// SECURITY: layered authorisation:
/// 1. functional `sessions:read` (Casbin) -- Capability to read ANY
///    session metadata at all.
/// 2. instance-level `session_access::verify(ReadMetadata)` --
///    ownership OR `sessions:supervise`, plus the access-rule
///    re-check. Without this layer, anyone with `sessions:read` could
///    GET any session UUID they happened to know.
pub async fn get_session(
    State(state): State<AppState>,
    user: AuthUser,
    perms: PermissionContext,
    Path(session_uuid_str): Path<String>,
) -> AppResult<Json<ProxySession>> {
    use crate::services::session_access::{self, SessionAccessOutcome};
    use shared::messages::SessionAccessIntent;

    if !perms.sessions_read {
        return Err(AppError::forbidden("sessions:read"));
    }

    match session_access::verify(
        &state,
        &session_uuid_str,
        &user,
        &perms,
        SessionAccessIntent::ReadMetadata,
    )
    .await
    {
        SessionAccessOutcome::Allowed => {}
        SessionAccessOutcome::Denied404 | SessionAccessOutcome::DeniedGone => {
            return Err(AppError::NotFound("Session not found".to_string()));
        }
    }

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
/// Holders of `sessions:bypass_access_rules` (superuser only) skip the
/// per-asset access rule check. Staff and regular users must have a
/// valid, active access rule linking their group to the asset's group
/// for the requested protocol.
pub async fn create_session(
    State(state): State<AppState>,
    user: AuthUser,
    perms: PermissionContext,
    Json(request): Json<CreateSessionRequest>,
) -> AppResult<Json<ProxySession>> {
    // NOTE: We do NOT gate on `perms.sessions_write` here. Regular users do
    // not hold that permission, yet they MUST be able to open sessions on
    // assets for which they have a valid access rule. The fine-grained gate
    // below (`perms.sessions_bypass_access_rules`) determines whether the
    // user can skip the per-asset access rule check.
    let _ = &user;

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

    if !perms.sessions_bypass_access_rules {
        let access_result = crate::services::access::can_access_asset(
            &state.access_client,
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
        industrial_protocol: None,
        ews_uuid: None,
        tunnel_target_addr: None,
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
    perms: PermissionContext,
    Path(session_uuid_str): Path<String>,
) -> AppResult<Response> {
    use crate::services::session_access::{self, SessionAccessOutcome};
    use shared::messages::SessionAccessIntent;

    // SECURITY: single seam. Allowed iff (caller is owner) OR
    // `sessions:write`. Every denial collapses to 404 -- in
    // particular a non-owner without `sessions:write` cannot
    // distinguish "session does not exist" from "you are not the
    // owner" through the status code.
    match session_access::verify(
        &state,
        &session_uuid_str,
        &user,
        &perms,
        SessionAccessIntent::Terminate,
    )
    .await
    {
        SessionAccessOutcome::Allowed => {}
        SessionAccessOutcome::Denied404 | SessionAccessOutcome::DeniedGone => {
            return Err(AppError::NotFound("Session not found".to_string()));
        }
    }

    let session_uuid = Uuid::parse_str(&session_uuid_str)
        .map_err(|_| AppError::Validation("Invalid UUID format".to_string()))?;

    let htmx = is_htmx_request(&headers);
    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    let session_row: ProxySession = proxy_sessions
        .filter(uuid.eq(session_uuid))
        .first(&mut conn)
        .await
        .map_err(|e| match e {
            diesel::result::Error::NotFound => AppError::NotFound("Session not found".to_string()),
            _ => AppError::Database(e),
        })?;
    drop(conn);

    // Shared terminate core: DB update (+ recording fields), hydration
    // enqueue, proxy-side force-close (SSH/RDP/IACS). Same seam as
    // account deactivation and the JIT grant revocation cascade.
    let updated_session = crate::services::session_termination::terminate_live_session(
        &state,
        &session_row,
        "user_terminated",
    )
    .await?;

    crate::services::emit_audit(
        &state,
        crate::ipc::AuditEvent::new(shared::messages::AuditEventType::SessionTerminated, "{}")
            .user(user.uuid.clone())
            .session(session_uuid.to_string()),
    );

    // Push real-time updates to /sessions and /sessions/active page subscribers
    crate::services::session_termination::broadcast_session_list_updates(&state).await;

    if htmx {
        // Return an updated HTML fragment for the session row
        let html = r#"<li class="px-6 py-4 hover:bg-gray-50 dark:hover:bg-gray-700">
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
                                    Session terminated
                                </p>
                                <span class="ml-2 inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium bg-red-100 text-red-800 dark:bg-red-900/50 dark:text-red-300">
                                    Terminated
                                </span>
                            </div>
                            <div class="mt-1 flex items-center text-sm text-gray-500 dark:text-gray-400">
                                <span>Session disconnected by administrator</span>
                            </div>
                        </div>
                    </div>
                </div>
            </li>"#;
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

    /// The handler must route through the shared terminate core (the
    /// four side-effects live there; see
    /// `services/session_termination.rs`), not re-implement it inline.
    #[test]
    fn test_terminate_session_routes_through_shared_core() {
        let body = terminate_session_body();
        assert!(
            body.contains("session_termination::terminate_live_session"),
            "terminate_session must delegate to services::session_termination"
        );
    }

    #[test]
    fn test_terminate_session_broadcasts_list_updates() {
        let body = terminate_session_body();
        assert!(
            body.contains("session_termination::broadcast_session_list_updates"),
            "terminate_session must push real-time /sessions + /sessions/active updates"
        );
    }

    const TERMINATION_SERVICE: &str = include_str!("../../services/session_termination.rs");

    /// The shared core must keep the proxy force-close side-effects the
    /// handler carried before the extraction.
    #[test]
    fn test_termination_service_closes_and_unsubscribes_proxies() {
        for needle in [
            "close_session",
            "unsubscribe_session",
            "SessionType::Ssh",
            "SessionType::Rdp",
            "SessionType::IacsTunnel",
        ] {
            assert!(
                TERMINATION_SERVICE.contains(needle),
                "session_termination service must contain `{needle}`"
            );
        }
    }

    /// The shared broadcast helper must keep both page refresh pushes.
    #[test]
    fn test_termination_service_pushes_both_list_updates() {
        for needle in ["push_session_list_update", "push_active_sessions_update"] {
            assert!(
                TERMINATION_SERVICE.contains(needle),
                "broadcast_session_list_updates must call `{needle}`"
            );
        }
    }
}
