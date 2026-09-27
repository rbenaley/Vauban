//! MCP mid-session policy recheck (M9 / Borne).
//!
//! **Primary path (instant):** [`notify_policy_changed`] runs on every
//! access-rule create/update/delete. It recomputes ∩ tools and pushes
//! `McpSessionUpdate` over IPC **immediately** — the proxy refuses a
//! removed tool on the next `tools/call` (`-32001`). No 30 s wait.
//!
//! **Safety net:** a background loop still runs every
//! [`RECHECK_INTERVAL_SECS`] for external / missed mutations.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use uuid::Uuid;

use crate::AppState;
use crate::ipc::{McpSessionUpdateRequest, ProxyMcpClient};
use crate::models::asset::Asset;
use crate::models::session::SessionType;
use crate::services::mcp_discover::{catalog_from_asset, tool_constraints_json_for_session_extra};
use crate::services::mcp_session::{
    ENVELOPE_MAX_CALLS, ENVELOPE_WINDOW_SECONDS, resolve_rule_hitl_tools,
    resolve_rule_require_plan_tools,
};

/// Background safety-net interval (not the primary revocation path).
pub const RECHECK_INTERVAL_SECS: u64 = 30;

/// Instant push after an access-rule mutation (preferred UX path).
///
/// 1. Lot 0 / V-8: [`policy_recheck::run_once_shared`] — Access deny / expire /
///    MFA-approval (false→true delta) / duration shrink for
///    IACS+SSH+RDP+MCP (immediate, not waiting 30 s).
/// 2. MCP V-7: tool ∩ shrink via IPC (+ api_key inactive / empty tools).
pub async fn notify_policy_changed(state: &AppState) {
    let mut failures = crate::services::policy_recheck::FailureTracker::default();
    let (cut, filled) =
        crate::services::policy_recheck::run_once_shared(state, &mut failures).await;
    let (updated, terminated) = run_once(state).await;
    if cut > 0 || filled > 0 || updated > 0 || terminated > 0 {
        tracing::info!(
            access_cut = cut,
            soft_filled = filled,
            mcp_updated = updated,
            mcp_terminated = terminated,
            "policy: live sessions refreshed after access-rule change (immediate)"
        );
    }
}

/// One pass over active MCP sessions.
///
/// Returns `(updated, terminated)`.
pub async fn run_once(state: &AppState) -> (usize, usize) {
    let pool = &state.db_pool;
    let proxy_mcp = state.proxy_mcp.as_ref();
    let mut conn = match pool.get().await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "mcp recheck: DB pool unavailable, skipping tick");
            return (0, 0);
        }
    };

    use crate::schema::{assets, proxy_sessions, users};

    #[derive(Queryable)]
    struct LiveMcp {
        id: i32,
        uuid: Uuid,
        user_id: i32,
        user_uuid: Uuid,
        asset_id: i32,
        expires_at: Option<chrono::DateTime<Utc>>,
        user_active: bool,
        user_deleted: bool,
        metadata: serde_json::Value,
    }

    // P6-2b: include ops-paused `suspended` so IAM suspension/revocation
    // still cuts visits that are not `active`.
    let rows: Vec<LiveMcp> = match proxy_sessions::table
        .inner_join(users::table.on(users::id.eq(proxy_sessions::user_id)))
        .filter(proxy_sessions::session_type.eq(SessionType::Mcp.as_str()))
        .filter(proxy_sessions::status.eq_any(["active", "suspended"]))
        .select((
            proxy_sessions::id,
            proxy_sessions::uuid,
            proxy_sessions::user_id,
            users::uuid,
            proxy_sessions::asset_id,
            proxy_sessions::expires_at,
            users::is_active,
            users::is_deleted,
            proxy_sessions::metadata,
        ))
        .load::<LiveMcp>(&mut conn)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "mcp recheck: list sessions failed");
            return (0, 0);
        }
    };

    if rows.is_empty() {
        return (0, 0);
    }

    let now = Utc::now();
    let mut updated = 0usize;
    let mut terminated = 0usize;

    for row in rows {
        let session_id = row.uuid.to_string();
        let reason_expire = row.expires_at.is_some_and(|e| e <= now);
        if row.user_deleted || !row.user_active || reason_expire {
            let reason = if row.user_deleted {
                "user_deleted"
            } else if !row.user_active {
                "user_inactive"
            } else {
                "session_expired"
            };
            if terminate_mcp(
                state,
                &mut conn,
                proxy_mcp,
                row.id,
                &session_id,
                Some(&row.user_uuid.to_string()),
                reason,
            )
            .await
            {
                terminated += 1;
            }
            continue;
        }

        // Agent sessions: inactive / expired API key → terminate (V-8).
        if let Some(key_id) = row
            .metadata
            .get("api_key_id")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
        {
            use crate::schema::api_keys;
            let key_status: Option<(bool, Option<chrono::DateTime<Utc>>)> =
                match Uuid::parse_str(key_id) {
                    Ok(kuuid) => api_keys::table
                        .filter(api_keys::uuid.eq(kuuid))
                        .select((api_keys::is_active, api_keys::expires_at))
                        .first::<(bool, Option<chrono::DateTime<Utc>>)>(&mut conn)
                        .await
                        .optional()
                        .unwrap_or(None),
                    Err(_) => None,
                };
            let key_dead = match key_status {
                None => true, // unknown / deleted key
                Some((false, _)) => true,
                Some((true, Some(exp))) if exp <= now => true,
                Some((true, _)) => false,
            };
            if key_dead {
                if terminate_mcp(
                    state,
                    &mut conn,
                    proxy_mcp,
                    row.id,
                    &session_id,
                    Some(&row.user_uuid.to_string()),
                    "api_key_inactive",
                )
                .await
                {
                    terminated += 1;
                }
                continue;
            }
        }

        let asset: Asset = match assets::table
            .filter(assets::id.eq(row.asset_id))
            .filter(assets::is_deleted.eq(false))
            .first(&mut conn)
            .await
        {
            Ok(a) => a,
            Err(_) => {
                if terminate_mcp(
                    state,
                    &mut conn,
                    proxy_mcp,
                    row.id,
                    &session_id,
                    Some(&row.user_uuid.to_string()),
                    "asset_gone",
                )
                .await
                {
                    terminated += 1;
                }
                continue;
            }
        };

        let tools = match state
            .access_client
            .compute_mcp_effective_tools(&row.user_uuid.to_string(), &asset.uuid.to_string())
            .await
        {
            Ok(t) => Some(t),
            Err(e) => {
                tracing::warn!(
                    session_id = %session_id,
                    error = %e,
                    "mcp recheck: Access ComputeMcpEffectiveTools failed — terminating (fail-closed)"
                );
                if terminate_mcp(
                    state,
                    &mut conn,
                    proxy_mcp,
                    row.id,
                    &session_id,
                    Some(&row.user_uuid.to_string()),
                    "access_check_failed",
                )
                .await
                {
                    terminated += 1;
                }
                continue;
            }
        };

        // Empty whitelist (no rules / ∩ empty / tool removed until none left)
        // → terminate now (V-8 style), do not leave a dead session.
        let Some(list) = tools.filter(|t| !t.is_empty()) else {
            if terminate_mcp(
                state,
                &mut conn,
                proxy_mcp,
                row.id,
                &session_id,
                Some(&row.user_uuid.to_string()),
                "no_tools_granted",
            )
            .await
            {
                terminated += 1;
            }
            continue;
        };

        // Instant shrink + HITL/constraint tighten: push ∩ + catalogue HITL
        // to proxy (T1 never-widen). Next tools/call for a removed tool → -32001;
        // newly HITL-flagged tools gate mid-session. Do NOT send
        // envelope_on_exceed=throttle (would clobber asset suspend mode).
        let rule_hitl = resolve_rule_hitl_tools(&mut conn, row.user_id, &asset)
            .await
            .unwrap_or_default();
        let rule_plan = resolve_rule_require_plan_tools(&mut conn, row.user_id, &asset)
            .await
            .unwrap_or_default();
        let constraints = tool_constraints_json_for_session_extra(
            &catalog_from_asset(&asset),
            &rule_hitl,
            &rule_plan,
        );
        if push_update(state, proxy_mcp, &session_id, Some(list), &constraints).await {
            updated += 1;
        } else if terminate_mcp(
            state,
            &mut conn,
            proxy_mcp,
            row.id,
            &session_id,
            Some(&row.user_uuid.to_string()),
            "policy_update_failed",
        )
        .await
        {
            tracing::warn!(
                session_id = %session_id,
                "mcp policy: whitelist shrink did not reach proxy — session terminated"
            );
            terminated += 1;
        }
    }

    if updated > 0 || terminated > 0 {
        tracing::info!(updated, terminated, "mcp recheck tick");
    }
    (updated, terminated)
}

async fn push_update(
    _state: &AppState,
    proxy_mcp: Option<&Arc<ProxyMcpClient>>,
    session_id: &str,
    allowed_tools: Option<Vec<String>>,
    tool_constraints_json: &str,
) -> bool {
    // Production path: Capsicum IPC first (HTTP /sessions/*/update is lab-only).
    if let Some(proxy) = proxy_mcp {
        let req = McpSessionUpdateRequest {
            session_id: session_id.to_string(),
            allowed_tools: allowed_tools.clone(),
            tool_constraints_json: tool_constraints_json.to_string(),
            envelope_max_calls: ENVELOPE_MAX_CALLS,
            envelope_window_seconds: ENVELOPE_WINDOW_SECONDS,
            // Empty = leave live on_exceed unchanged (preserve suspend).
            envelope_on_exceed: String::new(),
            expires_at: None,
        };
        match proxy.update_session(req) {
            Ok(()) => {
                tracing::debug!(
                    session_id = %session_id,
                    "mcp policy: whitelist/HITL shrink pushed via IPC (immediate)"
                );
                return true;
            }
            Err(e) => {
                tracing::warn!(
                    session_id = %session_id,
                    error = %e,
                    "mcp policy: IPC update failed"
                );
            }
        }
    }

    tracing::warn!(
        session_id = %session_id,
        "mcp policy: no IPC update — skip"
    );
    false
}

async fn terminate_mcp(
    state: &AppState,
    conn: &mut crate::db::DbConnection,
    proxy_mcp: Option<&Arc<ProxyMcpClient>>,
    session_pk: i32,
    session_id: &str,
    user_uuid: Option<&str>,
    reason: &str,
) -> bool {
    terminate_mcp_with_actor(
        state,
        conn,
        proxy_mcp,
        session_pk,
        session_id,
        user_uuid,
        reason,
        crate::services::access_decision::ACTOR_MCP_RECHECK,
    )
    .await
}

/// Cut a live MCP row and mint an R0 `decision_id` (contestable).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn terminate_mcp_with_actor(
    state: &AppState,
    conn: &mut crate::db::DbConnection,
    proxy_mcp: Option<&Arc<ProxyMcpClient>>,
    session_pk: i32,
    session_id: &str,
    user_uuid: Option<&str>,
    reason: &str,
    actor: &str,
) -> bool {
    use crate::schema::proxy_sessions;
    use crate::services::access_decision::mint_decision_id;

    let now = Utc::now();
    let decision_id = mint_decision_id();
    let source_group_id: Option<i32> = proxy_sessions::table
        .filter(proxy_sessions::id.eq(session_pk))
        .select(proxy_sessions::decision_source_group_id)
        .first::<Option<i32>>(conn)
        .await
        .ok()
        .flatten();
    let mcp_recording = state.config.recording.mcp_recording_enabled();
    let update = if mcp_recording {
        let rec_path = crate::services::recording_hydrator::recording_dir_for_session(
            &state.config.recording.storage_path,
            session_id,
            now,
        );
        diesel::update(proxy_sessions::table.filter(proxy_sessions::id.eq(session_pk)))
            .set((
                proxy_sessions::status.eq("terminated"),
                proxy_sessions::disconnected_at.eq(now),
                proxy_sessions::updated_at.eq(now),
                proxy_sessions::is_recorded.eq(true),
                proxy_sessions::recording_path.eq(&rec_path),
                proxy_sessions::decision_id.eq(&decision_id),
                proxy_sessions::termination_reason.eq(reason),
                proxy_sessions::decision_actor.eq(actor),
                proxy_sessions::decision_at.eq(now),
            ))
            .execute(conn)
            .await
    } else {
        diesel::update(proxy_sessions::table.filter(proxy_sessions::id.eq(session_pk)))
            .set((
                proxy_sessions::status.eq("terminated"),
                proxy_sessions::disconnected_at.eq(now),
                proxy_sessions::updated_at.eq(now),
                proxy_sessions::decision_id.eq(&decision_id),
                proxy_sessions::termination_reason.eq(reason),
                proxy_sessions::decision_actor.eq(actor),
                proxy_sessions::decision_at.eq(now),
            ))
            .execute(conn)
            .await
    };
    if let Err(e) = update {
        tracing::warn!(session_id = %session_id, error = %e, "mcp recheck: DB terminate failed");
        return false;
    }

    crate::services::access_decision::emit_mcp_access_decision_with_group(
        state,
        &decision_id,
        session_id,
        user_uuid,
        reason,
        actor,
        source_group_id,
    )
    .await;

    if mcp_recording {
        let grace = Duration::from_secs(state.config.recording.hydration_enqueue_delay_secs);
        std::mem::drop(crate::services::recording_hydrator::enqueue_hydration(
            state, session_pk, grace,
        ));
    }

    if let Some(proxy) = proxy_mcp {
        let _ = proxy.terminate_session(session_id, reason);
    }

    tracing::info!(
        session_id = %session_id,
        reason,
        decision_id = %decision_id,
        "mcp recheck: session terminated"
    );
    true
}

/// Spawn the background safety-net loop.
pub fn spawn_recheck(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(RECHECK_INTERVAL_SECS));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let _ = run_once(&state).await;
        }
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn interval_is_thirty_seconds() {
        assert_eq!(super::RECHECK_INTERVAL_SECS, 30);
    }

    #[test]
    fn terminate_uses_ipc_not_lab_http() {
        let src = include_str!("mcp_recheck.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap_or(src);
        assert!(
            prod.contains("proxy.terminate_session"),
            "recheck must cut the visit over proxy_mcp IPC"
        );
        assert!(
            !prod.contains("127.0.0.1:19443/session"),
            "recheck must not call the lab HTTP control plane"
        );
        assert!(
            !prod.contains(concat!("lab_http_", "control_plane_allowed")),
            "the lab HTTP gate must not be compiled"
        );
    }
}
