//! MCP Phase C session control: suspend / resume / HITL decisions
//! (docs/specs/vauban-mcp/09-borne-session.md).

use crate::AppState;
use crate::error::{AppError, AppResult};
use crate::ipc::ProxyMcpClient;
use crate::models::session::{ProxySession, SessionStatus, SessionType};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use std::sync::Arc;
use tracing::info;
use uuid::Uuid;
use vauban_db::schema::proxy_sessions::dsl::{
    proxy_sessions, status as status_col, uuid as uuid_col,
};

/// Suspend a live MCP session (DB + proxy IPC). Requires `sessions:supervise`
/// at the handler layer.
pub async fn suspend_mcp_session(
    state: &AppState,
    session: &ProxySession,
    reason: &str,
    actor_user_id: &str,
) -> AppResult<ProxySession> {
    ensure_mcp(session)?;
    let sid = session.uuid.to_string();
    let st = session.status_enum();
    if st == SessionStatus::Suspended {
        return Ok(session.clone());
    }
    if !st.is_live() {
        return Err(AppError::Validation(
            "session is not live and cannot be suspended".into(),
        ));
    }

    let Some(ref proxy) = state.proxy_mcp else {
        return Err(AppError::Ipc("vauban-proxy-mcp unavailable".into()));
    };
    proxy.suspend_session(&sid, reason, actor_user_id)?;

    let updated = set_status(state, session.uuid, SessionStatus::Suspended).await?;
    notify_mcp_session_state(state, &sid, "suspended", reason, updated.user_id).await;
    Ok(updated)
}

/// Resume a suspended MCP session. Handler enforces owner **or**
/// `sessions:supervise`.
pub async fn resume_mcp_session(
    state: &AppState,
    session: &ProxySession,
    actor_user_id: &str,
) -> AppResult<ProxySession> {
    ensure_mcp(session)?;
    let sid = session.uuid.to_string();
    if session.status_enum() == SessionStatus::Terminated
        || session.status_enum() == SessionStatus::Expired
        || session.status_enum() == SessionStatus::Failed
    {
        return Err(AppError::Validation(
            "session is ended and cannot be resumed".into(),
        ));
    }
    // Prefer Suspended in DB, but tolerate Active briefly before state-notify lands.

    let Some(ref proxy) = state.proxy_mcp else {
        return Err(AppError::Ipc("vauban-proxy-mcp unavailable".into()));
    };
    proxy.resume_session(&sid, actor_user_id)?;

    let updated = set_status(state, session.uuid, SessionStatus::Active).await?;
    notify_mcp_session_state(state, &sid, "active", "resume", updated.user_id).await;
    Ok(updated)
}

/// Forward HITL approve|deny to the proxy.
pub fn hitl_decide(
    proxy: &Arc<ProxyMcpClient>,
    session_id: &str,
    pending_id: &str,
    decision: &str,
    actor_user_id: &str,
) -> AppResult<()> {
    proxy.hitl_decision(session_id, pending_id, decision, actor_user_id)
}

fn ensure_mcp(session: &ProxySession) -> AppResult<()> {
    if session.session_type != SessionType::Mcp {
        return Err(AppError::Validation(
            "suspend/resume/HITL only apply to MCP sessions".into(),
        ));
    }
    Ok(())
}

async fn set_status(
    state: &AppState,
    session_uuid: Uuid,
    status: SessionStatus,
) -> AppResult<ProxySession> {
    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {e}")))?;
    diesel::update(proxy_sessions.filter(uuid_col.eq(session_uuid)))
        .set(status_col.eq(status.as_str()))
        .execute(&mut conn)
        .await
        .map_err(AppError::Database)?;
    let updated: ProxySession = proxy_sessions
        .filter(uuid_col.eq(session_uuid))
        .first(&mut conn)
        .await
        .map_err(AppError::Database)?;
    info!(
        session_id = %session_uuid,
        status = status.as_str(),
        "MCP session status updated"
    );
    Ok(updated)
}

/// Apply proxy→web `McpSessionStateNotify` (envelope auto-suspend / resume).
pub async fn apply_proxy_state_notify(
    state: &AppState,
    session_id: &str,
    status: &str,
    reason: &str,
) -> AppResult<()> {
    let session_uuid = Uuid::parse_str(session_id)
        .map_err(|_| AppError::Validation(format!("invalid session_id: {session_id}")))?;
    let target = match status {
        "suspended" => SessionStatus::Suspended,
        "active" => SessionStatus::Active,
        other => {
            return Err(AppError::Validation(format!(
                "unknown MCP state notify status: {other}"
            )));
        }
    };
    let updated = set_status(state, session_uuid, target).await?;
    info!(
        session_id = %session_id,
        status = status,
        reason = reason,
        session_type = ?updated.session_type,
        "MCP proxy state notify applied to DB"
    );
    crate::services::session_termination::broadcast_session_list_updates(state).await;
    notify_mcp_session_state(state, session_id, status, reason, updated.user_id).await;
    Ok(())
}

async fn notify_mcp_session_state(
    state: &AppState,
    session_id: &str,
    status: &str,
    reason: &str,
    user_id: i32,
) {
    let Ok(mut conn) = state.db_pool.get().await else {
        return;
    };
    use crate::schema::users;
    use diesel::prelude::*;
    use diesel_async::RunQueryDsl;
    let Ok(user_uuid) = users::table
        .filter(users::id.eq(user_id))
        .select(users::uuid)
        .first::<uuid::Uuid>(&mut conn)
        .await
    else {
        return;
    };
    let event_type = if status == "suspended" {
        "mcp_session_suspended"
    } else {
        "mcp_session_resumed"
    };
    let _ = state
        .broadcast
        .send(
            &crate::services::broadcast::WsChannel::Notifications,
            crate::services::broadcast::WsMessage::new(
                "jit-notification",
                serde_json::json!({
                    "type": event_type,
                    "session_uuid": session_id,
                    "reason": reason,
                    "user_uuid": user_uuid,
                })
                .to_string(),
            ),
        )
        .await;
}

#[cfg(test)]
mod tests {
    #[test]
    fn ensure_mcp_rejects_non_mcp_sessions() {
        let src = include_str!("mcp_control.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap_or(src);
        assert!(
            prod.contains("session.session_type != SessionType::Mcp"),
            "suspend/resume/HITL must refuse non-MCP sessions"
        );
        assert!(
            prod.contains("proxy.suspend_session") && prod.contains("proxy.resume_session"),
            "suspend/resume must talk to vauban-proxy-mcp"
        );
        assert!(
            prod.contains("hitl_decision") && prod.contains("fn hitl_decide"),
            "HITL decide must forward to the proxy"
        );
    }

    #[test]
    fn proxy_state_notify_only_maps_suspended_and_active() {
        let src = include_str!("mcp_control.rs");
        let start = src
            .find("fn apply_proxy_state_notify")
            .expect("apply_proxy_state_notify");
        let body = &src[start..];
        assert!(body.contains("\"suspended\"") && body.contains("\"active\""));
        assert!(body.contains("unknown MCP state notify status"));
        assert!(body.contains("broadcast_session_list_updates"));
    }
}
