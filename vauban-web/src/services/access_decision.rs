//! TRUSTED R0 — addressable access decisions for MCP session cuts.
//!
//! When a live MCP visit is terminated or restricted, mint a stable
//! `decision_id` (dossier number), persist it on `proxy_sessions`, and
//! emit a critical WORM `McpAccessDecision` event. Contestation (R1)
//! hangs off this id; R1+ stamps `decision_source_group_id` on group remove.
//!
//! Machine codes stay in DB/WORM; UI uses [`reason_label`] / [`actor_label`].

use crate::AppState;
use crate::ipc::AuditEvent;
use crate::schema::proxy_sessions;
use crate::services::audit::emit_audit_critical;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use shared::messages::AuditEventType;
use uuid::Uuid;

/// Actor string for the MCP safety-net recheck loop.
pub const ACTOR_MCP_RECHECK: &str = "system:mcp_recheck";

/// Actor for Mission Seal CheckStep drift (IAM suspension).
pub const ACTOR_MANDATE_DRIFT: &str = "system:mandate_drift";

/// Actor string for the shared terminate core (admin API, deactivate,
/// policy_recheck, JIT cascade, …).
pub const ACTOR_TERMINATE_LIVE: &str = "system:terminate_live_session";

/// Mint a stable, human-readable decision id (`D-<uuid>`).
#[must_use]
pub fn mint_decision_id() -> String {
    format!("D-{}", Uuid::new_v4())
}

/// Operator-facing label for a stored `termination_reason` code.
#[must_use]
pub fn reason_label(reason: &str) -> &'static str {
    match reason {
        "user_terminated" => "Ended by an administrator or API call",
        "account_deactivated" => "User account was deactivated",
        "user_deleted" => "User account was soft-deleted (revocation)",
        "user_inactive" => "User account is inactive",
        "session_expired" => "Session reached its end time",
        "api_key_inactive" => "API key revoked or rotated (compromise response)",
        "asset_gone" => "Target asset is no longer available",
        "access_revoked" => "Removed from access group (IAM suspension)",
        "mandate_drift" => "Mission Seal drift — visit cut (IAM per access rule)",
        "access_check_failed" => "Access could not be verified (session ended for safety)",
        "access_unreachable" => "Access service was unreachable (session ended for safety)",
        "no_tools_granted" => "No tools remain authorized for this session",
        "approval_now_required" => "Approval is now required mid-session",
        "mfa_now_required" => "MFA is now required mid-session",
        _ => "Session access ended",
    }
}

/// Operator-facing label for a stored `decision_actor` code.
#[must_use]
pub fn actor_label(actor: &str) -> String {
    match actor {
        ACTOR_MCP_RECHECK => "Automatic access check".to_string(),
        ACTOR_MANDATE_DRIFT => "Mission Seal drift (automatic)".to_string(),
        ACTOR_TERMINATE_LIVE => "Administrator or system action".to_string(),
        other if other.starts_with("user:") => "Named user action".to_string(),
        other if other.starts_with("system:") => "System".to_string(),
        other => other.to_string(),
    }
}

/// Stamp live MCP sessions for `user_id` with the group about to cause
/// (or that caused) an access cut. Call **before** `notify_policy_changed`
/// on group-member remove so the subsequent terminate keeps the hint.
pub async fn stamp_live_mcp_source_group(state: &AppState, user_id: i32, group_id: i32) {
    let Ok(mut conn) = state.db_pool.get().await else {
        tracing::warn!(
            user_id,
            group_id,
            "R1+: stamp decision_source_group_id skipped (no DB conn)"
        );
        return;
    };
    match diesel::update(
        proxy_sessions::table
            .filter(proxy_sessions::user_id.eq(user_id))
            .filter(proxy_sessions::session_type.eq("mcp"))
            .filter(proxy_sessions::status.eq_any([
                "connecting",
                "active",
                "suspended",
                "approved",
            ])),
    )
    .set(proxy_sessions::decision_source_group_id.eq(group_id))
    .execute(&mut conn)
    .await
    {
        Ok(n) if n > 0 => {
            tracing::info!(
                user_id,
                group_id,
                stamped = n,
                "R1+: stamped decision_source_group_id on live MCP sessions"
            );
        }
        Ok(_) => {}
        Err(e) => {
            tracing::warn!(
                user_id,
                group_id,
                error = %e,
                "R1+: stamp decision_source_group_id failed"
            );
        }
    }
}

/// Emit critical WORM `McpAccessDecision` (forced seal when audit is wired).
pub async fn emit_mcp_access_decision(
    state: &AppState,
    decision_id: &str,
    session_uuid: &str,
    user_uuid: Option<&str>,
    reason: &str,
    actor: &str,
) {
    emit_mcp_access_decision_with_group(
        state,
        decision_id,
        session_uuid,
        user_uuid,
        reason,
        actor,
        None,
    )
    .await;
}

/// Like [`emit_mcp_access_decision`], optionally recording the source group.
pub async fn emit_mcp_access_decision_with_group(
    state: &AppState,
    decision_id: &str,
    session_uuid: &str,
    user_uuid: Option<&str>,
    reason: &str,
    actor: &str,
    source_group_id: Option<i32>,
) {
    let details = serde_json::json!({
        "decision_id": decision_id,
        "session_id": session_uuid,
        "reason": reason,
        "actor": actor,
        "source_group_id": source_group_id,
    })
    .to_string();
    let mut event = AuditEvent::new(AuditEventType::McpAccessDecision, details)
        .session(session_uuid.to_string());
    if let Some(uid) = user_uuid {
        event = event.user(uid.to_string());
    }
    if let Err(e) = emit_audit_critical(state, event).await {
        tracing::warn!(
            decision_id,
            session_id = %session_uuid,
            error = %e,
            "R0: McpAccessDecision critical emit failed (decision still on session row)"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_decision_id_has_d_prefix_and_uuid() {
        let id = mint_decision_id();
        assert!(id.starts_with("D-"), "expected D- prefix, got {id}");
        let rest = &id[2..];
        assert!(
            Uuid::parse_str(rest).is_ok(),
            "expected UUID after D-, got {rest}"
        );
    }

    #[test]
    fn reason_and_actor_labels_are_operator_facing() {
        assert_eq!(
            reason_label("access_revoked"),
            "Removed from access group (IAM suspension)"
        );
        assert_eq!(
            reason_label("mandate_drift"),
            "Mission Seal drift — visit cut (IAM per access rule)"
        );
        assert_eq!(
            actor_label(ACTOR_MANDATE_DRIFT),
            "Mission Seal drift (automatic)"
        );
        assert!(!reason_label("no_tools_granted").contains('_'));
        assert_eq!(actor_label(ACTOR_MCP_RECHECK), "Automatic access check");
        assert_eq!(
            actor_label(ACTOR_TERMINATE_LIVE),
            "Administrator or system action"
        );
        assert!(!actor_label(ACTOR_TERMINATE_LIVE).contains("terminate_live"));
        assert!(reason_label("api_key_inactive").contains("revoked or rotated"));
        assert!(reason_label("user_deleted").contains("soft-deleted"));
    }
}
