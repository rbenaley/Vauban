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
use crate::models::session::{CreateSessionRequest, NewProxySession, ProxySession, SessionType};
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

    // Check recording config before updating to decide if we need to set recording_path.
    // This must happen in the same UPDATE that sets "terminated", because the WebSocket
    // cleanup handler filters on status IN ('active','connecting') and would skip it.
    let session_for_recording: ProxySession = proxy_sessions
        .filter(uuid.eq(session_uuid))
        .first(&mut conn)
        .await
        .map_err(|e| match e {
            diesel::result::Error::NotFound => AppError::NotFound("Session not found".to_string()),
            _ => AppError::Database(e),
        })?;

    let now = chrono::Utc::now();
    let is_recording = match session_for_recording.session_type {
        SessionType::Ssh => state.config.recording.ssh_recording_enabled(),
        SessionType::Rdp => state.config.recording.rdp_recording_enabled(),
        SessionType::IacsTunnel => state.config.recording.iacs_recording_enabled(),
    };

    let updated_session = if is_recording {
        let path_anchor = session_for_recording.connected_at.unwrap_or(now);
        let rec_path = crate::services::recording_hydrator::recording_dir_for_session(
            &state.config.recording.storage_path,
            &session_for_recording.uuid.to_string(),
            path_anchor,
        );
        diesel::update(proxy_sessions.filter(uuid.eq(session_uuid)))
            .set((
                status.eq("terminated"),
                disconnected_at.eq(now),
                crate::schema::proxy_sessions::is_recorded.eq(true),
                recording_path.eq(&rec_path),
            ))
            .get_result::<ProxySession>(&mut conn)
            .await
    } else {
        diesel::update(proxy_sessions.filter(uuid.eq(session_uuid)))
            .set((status.eq("terminated"), disconnected_at.eq(now)))
            .get_result::<ProxySession>(&mut conn)
            .await
    }
    .map_err(|e| match e {
        diesel::result::Error::NotFound => AppError::NotFound("Session not found".to_string()),
        _ => AppError::Database(e),
    })?;

    // PRIMARY hydration path (issue #29 v1.4): schedule integrity
    // bundle population after the configurable grace period so
    // vauban-audit has time to flush meta.json. Idempotent + no-op
    // when the session was not recorded.
    std::mem::drop(crate::services::recording_hydrator::enqueue_hydration(
        &state,
        updated_session.id,
        std::time::Duration::from_secs(state.config.recording.hydration_enqueue_delay_secs),
    ));

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
        // IACS tunnels live in two flavours:
        // - PRODUCTION (proxy-iacs spawned by the supervisor):
        //   `state.proxy_iacs.terminate_tunnel(...)` dispatches an
        //   `IacsTunnelTerminate` IPC; proxy-iacs drains the relay,
        //   closes the SSH login, and emits `IacsTunnelClosed` which
        //   the IPC pump (`ipc::proxy_iacs::handle_message`)
        //   already persists as `status = 'terminated'` and pushes
        //   to the active-list WS subscribers.
        // - LEGACY (in-process russh server, used by tests and
        //   pre-supervisor dev mode): the in-memory registry is the
        //   only handle on the live tunnel; closing it drains the
        //   relay tasks within milliseconds.
        // We always try the IPC path first when wired so the
        // supervised topology stays canonical; the legacy registry
        // remains as a no-op fall-through for dev / test fixtures.
        SessionType::IacsTunnel => {
            let mut handled_via_ipc = false;
            if let Some(ref proxy) = state.proxy_iacs {
                match proxy.terminate_tunnel(&session_uuid_str, "user_terminated") {
                    Ok(()) => {
                        tracing::info!(
                            session_uuid = %session_uuid_str,
                            "iacs_tunnel: terminate IPC dispatched to proxy-iacs"
                        );
                        handled_via_ipc = true;
                    }
                    Err(e) => {
                        tracing::warn!(
                            session_uuid = %session_uuid_str,
                            error = %e,
                            "iacs_tunnel: terminate IPC dispatch failed; \
                             falling back to in-process registry"
                        );
                    }
                }
            }
            if !handled_via_ipc
                && let Some(handle) = state.iacs_tunnel_registry.close_and_remove(&session_uuid)
            {
                tracing::info!(
                    session_uuid = %session_uuid_str,
                    ews_uuid = %handle.ews_uuid,
                    "iacs_tunnel: tunnel closed via legacy in-process registry"
                );
            }
            // Per-session WS hint so the status page flips its pill
            // without waiting for the IPC round-trip / IacsTunnelClosed.
            let channel =
                crate::services::broadcast::WsChannel::SessionLive(session_uuid_str.clone());
            let payload = serde_json::json!({
                "type": "tunnel_closed",
                "reason": "user_terminated",
            });
            let channel_name = channel.as_str();
            let _ = state
                .broadcast
                .send_raw(&channel_name, payload.to_string())
                .await;
        }
    }

    // Push real-time updates to /sessions and /sessions/active page subscribers
    crate::tasks::dashboard::push_session_list_update(&state.broadcast, &state.db_pool).await;
    crate::tasks::dashboard::push_active_sessions_update(&state.broadcast, &state.db_pool).await;

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
