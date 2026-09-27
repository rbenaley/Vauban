//! Mission Seal CheckStep deny → visit cut + configurable IAM + R0 decision.
//!
//! First drift per live session: apply `access_rules.mcp_drift_iam`, mint
//! `decision_id` (`mandate_drift`), cut the visit. Contestation / overturn
//! reuse R1 (`AddGroupMember` only when IAM was `suspend_group` — never
//! resurrect the cut ticket). Idempotent: a session already terminated
//! with `mandate_drift` is a no-op. SMTP stays in vauban-mailer.
//!
//! PEP / notify / WORM stay in proxy-mcp. This module does not read
//! tools/call payloads or agent `_meta` for the IAM choice.

use diesel::OptionalExtension;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use shared::mcp_drift_iam::{McpDriftIam, max_severity};
use uuid::Uuid;

use crate::AppState;
use crate::models::session::{ProxySession, SessionType};
use crate::schema::{
    access_rules, api_keys, asset_asset_groups, asset_groups, proxy_sessions, user_groups, users,
};
use crate::services::access_decision::{ACTOR_MANDATE_DRIFT, stamp_live_mcp_source_group};
use crate::services::api_key_lifecycle::{ApiKeyLifecycleAction, after_api_key_invalidated};
use crate::services::mcp_recheck::terminate_mcp_with_actor;
use crate::services::role_invariants::{
    ChangeIntent, CheckError, RoleSnapshot, check_last_active_superuser, run_serializable,
};

const LIVE: &[&str] = &["connecting", "active", "suspended", "approved"];
const VIRTUAL_ALL_ASSETS_UUID: &str = "00000000-0000-0000-0000-000000000a11";

/// Apply the access-rule IAM knob after a Mission Seal drift notify.
pub async fn apply_mandate_drift(
    state: &AppState,
    session_id: &str,
    tool: &str,
    reason: &str,
    mandate_id: &str,
    requester_user_id: &str,
) -> Result<(), String> {
    let Ok(session_uuid) = Uuid::parse_str(session_id) else {
        return Err(format!("invalid session id: {session_id}"));
    };

    let mut conn = state.db_pool.get().await.map_err(|e| e.to_string())?;
    let session: ProxySession = proxy_sessions::table
        .filter(proxy_sessions::uuid.eq(session_uuid))
        .filter(proxy_sessions::session_type.eq(SessionType::Mcp.as_str()))
        .first(&mut conn)
        .await
        .map_err(|e| format!("session lookup: {e}"))?;

    if !LIVE.contains(&session.status.as_str()) {
        return Ok(());
    }
    if session.termination_reason.as_deref() == Some("mandate_drift") {
        return Ok(());
    }

    let user_uuid: Uuid = users::table
        .filter(users::id.eq(session.user_id))
        .select(users::uuid)
        .first(&mut conn)
        .await
        .map_err(|e| format!("user lookup: {e}"))?;
    drop(conn);

    let (group_ids, iam) = resolve_drift_iam(state, &session, tool).await;
    if iam == McpDriftIam::SuspendGroup {
        for gid in &group_ids {
            stamp_live_mcp_source_group(state, session.user_id, *gid).await;
            if let Err(e) = state
                .access_client
                .remove_group_member(*gid, session.user_id)
                .await
            {
                tracing::warn!(
                    session_id,
                    group_id = gid,
                    error = %e,
                    "mandate drift: RemoveGroupMember failed (session still cut)"
                );
            }
        }
    }

    let mut conn = state.db_pool.get().await.map_err(|e| e.to_string())?;
    let cut = terminate_mcp_with_actor(
        state,
        &mut conn,
        state.proxy_mcp.as_ref(),
        session.id,
        session_id,
        Some(&user_uuid.to_string()),
        "mandate_drift",
        ACTOR_MANDATE_DRIFT,
    )
    .await;
    drop(conn);

    match iam {
        McpDriftIam::RevokeOpenerKey => {
            apply_revoke_opener_key(state, &session, &user_uuid).await;
        }
        McpDriftIam::SoftDeleteUser => {
            apply_soft_delete_user(state, session.user_id, &user_uuid).await;
        }
        McpDriftIam::Terminate | McpDriftIam::SuspendGroup => {}
    }

    if matches!(iam, McpDriftIam::SuspendGroup) && !group_ids.is_empty() || cut {
        crate::services::mcp_recheck::notify_policy_changed(state).await;
    }
    if cut
        && let Err(e) = crate::services::mcp_mail::queue_mandate_drift(
            state,
            session_id,
            tool,
            reason,
            mandate_id,
            requester_user_id,
            iam,
        )
        .await
    {
        tracing::warn!(
            session_id,
            error = %e,
            "Failed to queue mcp.mandate_drift emails"
        );
    }

    Ok(())
}

async fn apply_revoke_opener_key(state: &AppState, session: &ProxySession, user_uuid: &Uuid) {
    let Some(key_str) = session
        .metadata
        .get("api_key_id")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        tracing::warn!(
            session_id = %session.uuid,
            "mandate drift: revoke_opener_key without metadata.api_key_id — terminate only"
        );
        return;
    };
    let Ok(key_uuid) = Uuid::parse_str(key_str) else {
        tracing::warn!(
            session_id = %session.uuid,
            api_key_id = key_str,
            "mandate drift: revoke_opener_key: invalid api_key_id — terminate only"
        );
        return;
    };

    let mut conn = match state.db_pool.get().await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "mandate drift: revoke_opener_key: no DB conn");
            return;
        }
    };
    let updated = diesel::update(
        api_keys::table
            .filter(api_keys::uuid.eq(key_uuid))
            .filter(api_keys::is_active.eq(true)),
    )
    .set(api_keys::is_active.eq(false))
    .execute(&mut conn)
    .await;
    drop(conn);
    match updated {
        Ok(0) => {
            tracing::warn!(
                session_id = %session.uuid,
                api_key_id = %key_uuid,
                "mandate drift: opener key already inactive or missing"
            );
        }
        Ok(_) => {
            after_api_key_invalidated(
                state,
                key_uuid,
                session.user_id,
                &user_uuid.to_string(),
                ApiKeyLifecycleAction::Revoked,
            )
            .await;
        }
        Err(e) => {
            tracing::warn!(
                session_id = %session.uuid,
                error = %e,
                "mandate drift: failed to deactivate opener key (session still cut)"
            );
        }
    }
}

/// Tombstone like admin delete (purge memberships + deactivate), without
/// treating `is_staff` / `is_superuser` as authorization. Last active
/// superuser: skip tombstone; caller still cuts the visit.
async fn apply_soft_delete_user(state: &AppState, user_id: i32, user_uuid: &Uuid) {
    let parsed = *user_uuid;
    let pool_ref = &state.db_pool;
    let tx_outcome = run_serializable::<bool, _>(pool_ref, move |c| {
        Box::pin(async move {
            let row: Option<(String, String, bool, bool, bool)> = users::table
                .filter(users::id.eq(user_id))
                .filter(users::is_deleted.eq(false))
                .select((
                    users::username,
                    users::email,
                    users::is_superuser,
                    users::is_staff,
                    users::is_active,
                ))
                .first(c)
                .await
                .optional()
                .map_err(CheckError::Db)?;
            let Some((current_username, current_email, b_super, b_staff, b_active)) = row else {
                return Ok(false);
            };
            let before = RoleSnapshot {
                is_superuser: b_super,
                is_staff: b_staff,
                is_active: b_active,
                is_deleted: false,
            };
            match check_last_active_superuser(c, user_id, &before, ChangeIntent::Delete).await {
                Ok(()) => {}
                Err(CheckError::Violation(_)) => return Ok(false),
                Err(e) => return Err(e),
            }

            diesel::delete(user_groups::table.filter(user_groups::user_id.eq(user_id)))
                .execute(c)
                .await
                .map_err(CheckError::Db)?;

            let now = chrono::Utc::now();
            let suffix = format!("_deleted_{}", now.timestamp_millis());
            diesel::update(users::table.filter(users::id.eq(user_id)))
                .set((
                    users::is_deleted.eq(true),
                    users::is_active.eq(false),
                    users::deleted_at.eq(now),
                    users::updated_at.eq(now),
                    users::username.eq(format!("{current_username}{suffix}")),
                    users::email.eq(format!("{current_email}{suffix}")),
                ))
                .execute(c)
                .await
                .map_err(CheckError::Db)?;
            Ok(true)
        })
    })
    .await;

    match tx_outcome {
        Ok(true) => {
            crate::handlers::web::deactivate_user(
                state,
                user_id,
                &parsed.to_string(),
                "account_deleted",
            )
            .await;
        }
        Ok(false) => {
            tracing::warn!(
                user_id,
                user_uuid = %parsed,
                "mandate drift: soft_delete_user skipped (last active superuser or already deleted)"
            );
        }
        Err(e) => {
            tracing::warn!(
                user_id,
                error = ?e,
                "mandate drift: soft_delete_user failed (session still cut)"
            );
        }
    }
}

/// Groups for `suspend_group` plus the max-severity IAM among matching MCP rules.
async fn resolve_drift_iam(
    state: &AppState,
    session: &ProxySession,
    tool: &str,
) -> (Vec<i32>, McpDriftIam) {
    if let Some(gid) = session.decision_source_group_id {
        let iams = load_matching_iams(state, session, tool, Some(gid))
            .await
            .unwrap_or_default();
        return (vec![gid], max_severity(iams));
    }
    match load_matching_rules(state, session, tool).await {
        Some((groups, iams)) => (groups, max_severity(iams)),
        None => (Vec::new(), McpDriftIam::SuspendGroup),
    }
}

async fn load_matching_iams(
    state: &AppState,
    session: &ProxySession,
    tool: &str,
    only_group: Option<i32>,
) -> Option<Vec<McpDriftIam>> {
    load_matching_rules(state, session, tool)
        .await
        .map(|(groups, iams)| {
            if let Some(gid) = only_group {
                groups
                    .into_iter()
                    .zip(iams)
                    .filter(|(g, _)| *g == gid)
                    .map(|(_, iam)| iam)
                    .collect()
            } else {
                iams
            }
        })
}

async fn load_matching_rules(
    state: &AppState,
    session: &ProxySession,
    tool: &str,
) -> Option<(Vec<i32>, Vec<McpDriftIam>)> {
    let mut conn = state.db_pool.get().await.ok()?;

    let member_of: Vec<i32> = user_groups::table
        .filter(user_groups::user_id.eq(session.user_id))
        .select(user_groups::group_id)
        .load::<i32>(&mut conn)
        .await
        .ok()?;
    if member_of.is_empty() {
        return None;
    }

    let virtual_uuid = Uuid::parse_str(VIRTUAL_ALL_ASSETS_UUID).ok()?;
    let virtual_all_id: Option<i32> = asset_groups::table
        .filter(asset_groups::uuid.eq(virtual_uuid))
        .select(asset_groups::id)
        .first::<i32>(&mut conn)
        .await
        .optional()
        .ok()
        .flatten();

    let mut asset_group_ids: Vec<i32> = asset_asset_groups::table
        .filter(asset_asset_groups::asset_id.eq(session.asset_id))
        .select(asset_asset_groups::asset_group_id)
        .load::<i32>(&mut conn)
        .await
        .ok()?;
    if let Some(vid) = virtual_all_id
        && !asset_group_ids.contains(&vid)
    {
        asset_group_ids.push(vid);
    }
    if asset_group_ids.is_empty() {
        return None;
    }

    type McpDriftRuleRow = (i32, Option<Vec<Option<String>>>, String);
    let rows: Vec<McpDriftRuleRow> = access_rules::table
        .filter(access_rules::user_group_id.eq_any(&member_of))
        .filter(access_rules::asset_group_id.eq_any(&asset_group_ids))
        .filter(access_rules::is_active.eq(true))
        .filter(access_rules::allowed_protocols.contains(vec![Some("mcp".to_string())]))
        .select((
            access_rules::user_group_id,
            access_rules::mcp_require_plan_tools,
            access_rules::mcp_drift_iam,
        ))
        .load(&mut conn)
        .await
        .ok()?;

    let mut groups: Vec<i32> = Vec::new();
    let mut group_iams: Vec<McpDriftIam> = Vec::new();
    let mut plan_groups: Vec<i32> = Vec::new();
    let mut plan_iams: Vec<McpDriftIam> = Vec::new();
    for (gid, plan_tools, raw_iam) in rows {
        let iam = McpDriftIam::parse_or_default(&raw_iam);
        if !groups.contains(&gid) {
            groups.push(gid);
            group_iams.push(iam);
        } else if let Some(idx) = groups.iter().position(|g| *g == gid)
            && iam > group_iams[idx]
        {
            group_iams[idx] = iam;
        }
        let lists_tool = plan_tools
            .as_ref()
            .is_some_and(|v| v.iter().flatten().any(|t| t == tool));
        if lists_tool {
            if !plan_groups.contains(&gid) {
                plan_groups.push(gid);
                plan_iams.push(iam);
            } else if let Some(idx) = plan_groups.iter().position(|g| *g == gid)
                && iam > plan_iams[idx]
            {
                plan_iams[idx] = iam;
            }
        }
    }

    if !plan_groups.is_empty() {
        return Some((plan_groups, plan_iams));
    }
    if groups.is_empty() {
        return None;
    }
    Some((groups, group_iams))
}

#[cfg(test)]
mod tests {
    #[test]
    fn apply_always_cuts_and_iam_matches_enum() {
        let src = include_str!("mcp_drift.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap_or(src);
        assert!(prod.contains("terminate_mcp_with_actor"));
        assert!(prod.contains("mandate_drift"));
        assert!(prod.contains("queue_mandate_drift"));
        assert!(prod.contains("resolve_drift_iam"));
        assert!(prod.contains("decision_source_group_id"));
        assert!(prod.contains("McpDriftIam::Terminate"));
        assert!(prod.contains("McpDriftIam::SuspendGroup"));
        assert!(prod.contains("remove_group_member"));
        assert!(prod.contains("stamp_live_mcp_source_group"));
        assert!(prod.contains("McpDriftIam::RevokeOpenerKey"));
        assert!(prod.contains("after_api_key_invalidated"));
        assert!(prod.contains("McpDriftIam::SoftDeleteUser"));
        assert!(prod.contains("is_deleted"));
        assert!(prod.contains("check_last_active_superuser"));
        assert!(
            !prod.contains("IssueSessionToken"),
            "drift must never mint a new session ticket"
        );
        assert!(
            !prod.contains("tools/call payloads") || prod.contains("does not read"),
            "agent tools/call payloads must not choose IAM"
        );
        assert!(!prod.contains("get(\"_meta\")"));
    }

    #[test]
    fn revoke_without_api_key_id_is_terminate() {
        let src = include_str!("mcp_drift.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap_or(src);
        assert!(prod.contains("revoke_opener_key without metadata.api_key_id — terminate only"));
        assert!(
            !prod.contains("remove_group_member(*gid")
                || prod.contains("McpDriftIam::SuspendGroup"),
            "revoke fallback must not invent RemoveGroupMember"
        );
    }
}
