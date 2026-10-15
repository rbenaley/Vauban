//! Shared core for forcefully terminating a LIVE proxy session
//! (SSH / RDP / IACS tunnel).
//!
//! Single seam ("terminate core"): the admin/API terminate endpoint
//! ([`crate::handlers::api::sessions::terminate_session`]), the account
//! deactivation sweep ([`crate::handlers::web::users::deactivate_user`])
//! and the JIT grant revocation cascade all route through
//! [`terminate_live_session`] so the four side-effects can never drift
//! apart between callers:
//!
//! 1. `proxy_sessions` UPDATE to `status = 'terminated'` +
//!    `disconnected_at` (and `is_recorded` / `recording_path` in the
//!    SAME statement -- the WebSocket cleanup handler filters on
//!    status IN ('active','connecting') and would skip a row already
//!    marked terminated).
//! 2. Recording hydration enqueue (idempotent, no-op when not
//!    recorded).
//! 3. Proxy-side force-close so the live data pump breaks immediately:
//!    SSH/RDP via `close_session` + `unsubscribe_session`, IACS via
//!    the `IacsTunnelTerminate` IPC + a per-session WS hint.
//! 4. NO list broadcasts here: callers batch them once via
//!    [`broadcast_session_list_updates`] (a deactivation or a
//!    revocation cascade may terminate several sessions).
//!
//! Structurally pinned by
//! `tests/web/jit_revocation_pins_test.rs::all_terminate_callers_use_the_shared_core`
//! (and `no_caller_reimplements_the_terminated_update`).

use crate::{
    AppState,
    error::{AppError, AppResult},
    models::session::{ProxySession, SessionType},
};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;

/// `termination_reason` when an administrator deletes the asset.
pub const REASON_ASSET_DELETED: &str = "asset_deleted";

/// `termination_reason` when an MCP asset's upstream address, transport or
/// TLS pin changes: open visits still hold the old pin and must reopen.
pub const REASON_ASSET_RECONFIGURED: &str = "asset_reconfigured";

/// Terminate one live proxy session. Returns the updated row.
///
/// `reason` flows into the IACS terminate IPC and the per-session WS
/// hint (e.g. `"user_terminated"`, `"account_deactivated"`,
/// `"access_revoked"`); the SSH/RDP close path has no reason channel
/// (the socket simply breaks and the WS loop emits its own close).
pub async fn terminate_live_session(
    state: &AppState,
    session: &ProxySession,
    reason: &str,
) -> AppResult<ProxySession> {
    use crate::schema::proxy_sessions;

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    let now = chrono::Utc::now();
    let is_recording = match session.session_type {
        SessionType::Ssh => state.config.recording.ssh_recording_enabled(),
        SessionType::Rdp => state.config.recording.rdp_recording_enabled(),
        SessionType::IacsTunnel => state.config.recording.iacs_recording_enabled(),
        SessionType::Mcp => state.config.recording.mcp_recording_enabled(),
    };

    let updated_session = if is_recording {
        let path_anchor = session.connected_at.unwrap_or(now);
        let rec_path = crate::services::recording_hydrator::recording_dir_for_session(
            &state.config.recording.storage_path,
            &session.uuid.to_string(),
            path_anchor,
        );
        diesel::update(proxy_sessions::table.filter(proxy_sessions::id.eq(session.id)))
            .set((
                proxy_sessions::status.eq("terminated"),
                proxy_sessions::disconnected_at.eq(now),
                proxy_sessions::is_recorded.eq(true),
                proxy_sessions::recording_path.eq(&rec_path),
            ))
            .get_result::<ProxySession>(&mut conn)
            .await
    } else {
        diesel::update(proxy_sessions::table.filter(proxy_sessions::id.eq(session.id)))
            .set((
                proxy_sessions::status.eq("terminated"),
                proxy_sessions::disconnected_at.eq(now),
            ))
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
        state,
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
        // IACS tunnels live exclusively in `vauban-proxy-iacs`.
        // `state.proxy_iacs.terminate_tunnel(...)` dispatches an
        // `IacsTunnelTerminate` IPC; proxy-iacs drains the relay,
        // closes the SSH login, and emits `IacsTunnelClosed` which
        // the IPC pump (`ipc::proxy_iacs::handle_message`) already
        // persists as `status = 'terminated'` and pushes to the
        // active-list WS subscribers. Belt-and-braces: even if the
        // IPC client is missing / the send fails, the row is already
        // `terminated`, so the revocation watchdog (2 s poll) cuts
        // the tunnel on its next tick when a client is wired.
        SessionType::IacsTunnel => {
            if let Some(ref proxy) = state.proxy_iacs {
                match proxy.terminate_tunnel(&session_uuid_str, reason) {
                    Ok(()) => {
                        tracing::info!(
                            session_uuid = %session_uuid_str,
                            reason = %reason,
                            "iacs_tunnel: terminate IPC dispatched to proxy-iacs"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            session_uuid = %session_uuid_str,
                            error = %e,
                            "iacs_tunnel: terminate IPC dispatch failed"
                        );
                    }
                }
            } else {
                tracing::error!(
                    session_uuid = %session_uuid_str,
                    "iacs_tunnel: proxy-iacs IPC client absent; cannot terminate live tunnel"
                );
            }
            // Per-session WS hint so the status page flips its pill
            // without waiting for the IPC round-trip / IacsTunnelClosed.
            let channel =
                crate::services::broadcast::WsChannel::SessionLive(session_uuid_str.clone());
            let payload = serde_json::json!({
                "type": "tunnel_closed",
                "reason": reason,
            });
            let channel_name = channel.as_str();
            let _ = state
                .broadcast
                .send_raw(&channel_name, payload.to_string())
                .await;
        }
        SessionType::Mcp => {
            if let Some(ref proxy) = state.proxy_mcp
                && let Err(e) = proxy.terminate_session(&session_uuid_str, reason)
            {
                tracing::warn!(
                    session_uuid = %session_uuid_str,
                    error = %e,
                    "mcp: terminate IPC dispatch failed"
                );
            }
            let decision_id = crate::services::access_decision::mint_decision_id();
            let _ =
                diesel::update(proxy_sessions::table.filter(proxy_sessions::uuid.eq(session.uuid)))
                    .set((
                        proxy_sessions::decision_id.eq(&decision_id),
                        proxy_sessions::termination_reason.eq(reason),
                        proxy_sessions::decision_actor
                            .eq(crate::services::access_decision::ACTOR_TERMINATE_LIVE),
                        proxy_sessions::decision_at.eq(now),
                    ))
                    .execute(&mut conn)
                    .await;
            crate::services::access_decision::emit_mcp_access_decision(
                state,
                &decision_id,
                &session_uuid_str,
                None,
                reason,
                "terminate_live_session",
            )
            .await;
        }
    }

    Ok(updated_session)
}

/// Terminate every open session (live or suspended, any protocol) on one
/// asset through [`terminate_live_session`], then refresh the session
/// lists once. Used when the asset itself is deleted or reconfigured:
/// the proxies only stop relaying when they are told, so a DB flip alone
/// leaves the visit running. Returns how many sessions were ended.
pub async fn terminate_open_sessions_on_asset(
    state: &AppState,
    asset_id: i32,
    reason: &str,
) -> AppResult<usize> {
    use crate::models::session::SessionStatus;
    use crate::schema::proxy_sessions;

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;
    let open: Vec<ProxySession> = proxy_sessions::table
        .filter(proxy_sessions::asset_id.eq(asset_id))
        .filter(proxy_sessions::status.eq_any(SessionStatus::OPEN_AS_STR))
        .load(&mut conn)
        .await
        .map_err(AppError::Database)?;
    drop(conn);

    let mut ended = 0usize;
    for session in &open {
        match terminate_live_session(state, session, reason).await {
            Ok(_) => ended += 1,
            Err(e) => tracing::warn!(
                session_uuid = %session.uuid,
                asset_id,
                reason,
                error = %e,
                "failed to terminate an open session on the asset"
            ),
        }
    }
    if ended > 0 {
        broadcast_session_list_updates(state).await;
    }
    Ok(ended)
}

/// An MCP asset's upstream moved (address, transport or TLS pin): open
/// visits still hold the old pin, so end them; agents reopen normally.
pub async fn end_visits_on_reconfigured_asset(state: &AppState, asset_id: i32) {
    if let Err(e) =
        terminate_open_sessions_on_asset(state, asset_id, REASON_ASSET_RECONFIGURED).await
    {
        tracing::error!(
            asset_id,
            error = %e,
            "asset reconfigured: could not end open visits; the recheck will retry"
        );
    }
}

/// Safety net for cuts that mark the DB row `terminated` before telling
/// the proxy: if that IPC was lost, no recheck would look at the row
/// again. Resend the proxy-side close for sessions ended because their
/// asset was deleted or reconfigured, or cut by the MCP access recheck,
/// within the longest window a ticket could still be alive. The proxies
/// treat a repeat as a no-op. Returns how many resends were dispatched.
pub async fn resend_lost_terminates(state: &AppState) -> usize {
    use crate::schema::{assets, proxy_sessions};
    use crate::services::access_decision::ACTOR_MCP_RECHECK;

    let Ok(mut conn) = state.db_pool.get().await else {
        return 0;
    };
    let since =
        chrono::Utc::now() - chrono::Duration::seconds(state.config.mcp.session_ttl_clamped());
    let rows: Vec<(uuid::Uuid, SessionType, Option<String>)> = match proxy_sessions::table
        .inner_join(assets::table.on(assets::id.eq(proxy_sessions::asset_id)))
        .filter(proxy_sessions::status.eq("terminated"))
        .filter(proxy_sessions::disconnected_at.ge(since))
        .filter(
            assets::is_deleted
                .eq(true)
                .or(proxy_sessions::termination_reason.eq(REASON_ASSET_RECONFIGURED))
                .or(proxy_sessions::decision_actor.eq(ACTOR_MCP_RECHECK)),
        )
        .select((
            proxy_sessions::uuid,
            proxy_sessions::session_type,
            proxy_sessions::termination_reason,
        ))
        .load(&mut conn)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "resend terminate: list failed");
            return 0;
        }
    };

    let mut resent = 0usize;
    for (uuid, session_type, stored_reason) in rows {
        let sid = uuid.to_string();
        let reason = stored_reason.as_deref().unwrap_or(REASON_ASSET_DELETED);
        let sent = match session_type {
            SessionType::Mcp => state
                .proxy_mcp
                .as_ref()
                .is_some_and(|p| p.terminate_session(&sid, reason).is_ok()),
            SessionType::Ssh => state
                .ssh_proxy
                .as_ref()
                .is_some_and(|p| p.close_session(&sid).is_ok()),
            SessionType::Rdp => state
                .rdp_proxy
                .as_ref()
                .is_some_and(|p| p.close_session(&sid).is_ok()),
            SessionType::IacsTunnel => state
                .proxy_iacs
                .as_ref()
                .is_some_and(|p| p.terminate_tunnel(&sid, reason).is_ok()),
        };
        if sent {
            resent += 1;
        }
    }
    resent
}

/// Push the /sessions and /sessions/active page refreshes once after a
/// termination batch. Kept separate from [`terminate_live_session`] so
/// multi-session callers (deactivation, revocation cascade) broadcast a
/// single update instead of one per terminated row.
pub async fn broadcast_session_list_updates(state: &AppState) {
    crate::tasks::dashboard::push_session_list_update(
        &state.broadcast,
        &state.db_pool,
        state.config.industrial.enabled,
    )
    .await;
    crate::tasks::dashboard::push_active_sessions_update(
        &state.broadcast,
        &state.db_pool,
        state.config.industrial.enabled,
    )
    .await;
}
