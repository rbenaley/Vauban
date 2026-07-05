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
//!    the `IacsTunnelTerminate` IPC (with the legacy in-process
//!    registry as dev/test fall-through) + a per-session WS hint.
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
        // Belt-and-braces: even if BOTH handles are missing, the row
        // is already `terminated`, so the proxy-iacs revocation
        // watchdog (2 s poll) cuts the tunnel on its next tick.
        SessionType::IacsTunnel => {
            let mut handled_via_ipc = false;
            if let Some(ref proxy) = state.proxy_iacs {
                match proxy.terminate_tunnel(&session_uuid_str, reason) {
                    Ok(()) => {
                        tracing::info!(
                            session_uuid = %session_uuid_str,
                            reason = %reason,
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
                && let Some(handle) = state
                    .iacs_tunnel_registry
                    .close_and_remove(&updated_session.uuid)
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
                "reason": reason,
            });
            let channel_name = channel.as_str();
            let _ = state
                .broadcast
                .send_raw(&channel_name, payload.to_string())
                .await;
        }
    }

    Ok(updated_session)
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
