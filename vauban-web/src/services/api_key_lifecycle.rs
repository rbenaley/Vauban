//! TRUSTED R2.2 — post-compromise API key (`vbn_`) lifecycle.
//!
//! On revoke or rotate: emit critical WORM + immediately terminate live
//! MCP sessions that were opened with that key (do not wait for recheck).

use crate::AppState;
use crate::ipc::AuditEvent;
use crate::models::session::ProxySession;
use crate::schema::{proxy_sessions, users};
use crate::services::audit::emit_audit_critical;
use crate::services::mcp_recheck;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use shared::messages::AuditEventType;
use uuid::Uuid;

/// Soft-revoke or rotate aftermath: kill live MCP visits for this key + WORM.
pub async fn after_api_key_invalidated(
    state: &AppState,
    key_uuid: Uuid,
    owner_user_id: i32,
    actor_user_uuid: &str,
    action: ApiKeyLifecycleAction,
) {
    let terminated = terminate_mcp_sessions_for_api_key(state, &key_uuid).await;
    let details = serde_json::json!({
        "api_key_id": key_uuid.to_string(),
        "owner_user_id": owner_user_id,
        "action": action.as_str(),
        "mcp_sessions_terminated": terminated,
    })
    .to_string();
    let event_type = match action {
        ApiKeyLifecycleAction::Revoked => AuditEventType::ApiKeyRevoked,
        ApiKeyLifecycleAction::Rotated => AuditEventType::ApiKeyRotated,
    };
    let _ = emit_audit_critical(
        state,
        AuditEvent::new(event_type, details).user(actor_user_uuid.to_string()),
    )
    .await;
    if terminated > 0 {
        mcp_recheck::notify_policy_changed(state).await;
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ApiKeyLifecycleAction {
    Revoked,
    Rotated,
}

impl ApiKeyLifecycleAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Revoked => "revoked",
            Self::Rotated => "rotated",
        }
    }
}

/// Terminate live MCP sessions whose `metadata.api_key_id` matches.
async fn terminate_mcp_sessions_for_api_key(state: &AppState, key_uuid: &Uuid) -> usize {
    let Ok(mut conn) = state.db_pool.get().await else {
        tracing::warn!("R2.2: no DB conn; cannot terminate MCP sessions for API key");
        return 0;
    };

    let key_str = key_uuid.to_string();
    let candidates: Vec<(ProxySession, Uuid)> = match proxy_sessions::table
        .inner_join(users::table.on(users::id.eq(proxy_sessions::user_id)))
        .filter(proxy_sessions::session_type.eq("mcp"))
        .filter(proxy_sessions::status.eq_any(["connecting", "active", "suspended", "approved"]))
        .select((ProxySession::as_select(), users::uuid))
        .load(&mut conn)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "R2.2: list MCP sessions for API key failed");
            return 0;
        }
    };

    let reason = "api_key_inactive";
    let mut n = 0usize;
    for (session, user_uuid) in candidates {
        let matches =
            session.metadata.get("api_key_id").and_then(|v| v.as_str()) == Some(key_str.as_str());
        if !matches {
            continue;
        }
        let session_id = session.uuid.to_string();
        match crate::services::session_termination::terminate_live_session(state, &session, reason)
            .await
        {
            Ok(_) => {
                n += 1;
                tracing::info!(
                    session_id = %session_id,
                    api_key_id = %key_str,
                    user = %user_uuid,
                    "R2.2: terminated MCP session after API key invalidation"
                );
            }
            Err(e) => {
                tracing::warn!(
                    session_id = %session_id,
                    error = %e,
                    "R2.2: terminate after API key invalidation failed"
                );
            }
        }
    }
    n
}
