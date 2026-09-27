//! TRUSTED R1 — open / claim / uphold / overturn access contestations.
//!
//! SoD: opener cannot claim or resolve their own contestation.
//! Overturn: `AddGroupMember` only — never resurrect old `vbw_`.

use crate::AppState;
use crate::error::{AppError, AppResult};
use crate::ipc::AuditEvent;
use crate::models::access_contestation::{
    AccessContestation, NewAccessContestation, STATUS_OPEN, STATUS_OVERTURNED, STATUS_UNDER_REVIEW,
    STATUS_UPHELD,
};
use crate::models::session::ProxySession;
use crate::schema::{access_contestations, proxy_sessions, users, vauban_groups};
use crate::services::audit::emit_audit_critical;
use chrono::Utc;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use shared::messages::AuditEventType;
use uuid::Uuid;

const OPEN_REASON_MIN: usize = 10;
const OPEN_REASON_MAX: usize = 1000;

/// Open a contestation against a session's R0 `decision_id`.
pub async fn open_contestation(
    state: &AppState,
    session: &ProxySession,
    opener_user_id: i32,
    open_reason: &str,
) -> AppResult<AccessContestation> {
    let decision_id = session.decision_id.as_ref().ok_or_else(|| {
        AppError::Validation("This session has no access decision to contest".into())
    })?;
    if session.session_type.as_str() != "mcp" {
        return Err(AppError::Validation(
            "Contestation is currently available for MCP sessions only".into(),
        ));
    }
    let reason = open_reason.trim();
    let len = reason.len();
    if !(OPEN_REASON_MIN..=OPEN_REASON_MAX).contains(&len) {
        return Err(AppError::Validation(format!(
            "Contestation reason must be {OPEN_REASON_MIN}..{OPEN_REASON_MAX} characters"
        )));
    }
    if session.termination_reason.as_deref() == Some("user_deleted") {
        return Err(AppError::Validation(
            "Account revocation cannot be overturned via contestation — contact an administrator"
                .into(),
        ));
    }

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {e}")))?;

    let existing: Option<i64> = access_contestations::table
        .filter(access_contestations::decision_id.eq(decision_id))
        .filter(access_contestations::status.eq_any([STATUS_OPEN, STATUS_UNDER_REVIEW]))
        .select(access_contestations::id)
        .first(&mut conn)
        .await
        .optional()
        .map_err(AppError::Database)?;
    if existing.is_some() {
        return Err(AppError::Validation(
            "An open contestation already exists for this decision".into(),
        ));
    }

    let row = NewAccessContestation {
        uuid: Uuid::new_v4(),
        decision_id: decision_id.clone(),
        session_uuid: session.uuid,
        subject_user_id: session.user_id,
        status: STATUS_OPEN.to_string(),
        opened_by_id: opener_user_id,
        open_reason: reason.to_string(),
    };

    let created: AccessContestation = diesel::insert_into(access_contestations::table)
        .values(&row)
        .get_result(&mut conn)
        .await
        .map_err(AppError::Database)?;

    drop(conn);

    let details = serde_json::json!({
        "contestation_id": created.uuid.to_string(),
        "decision_id": created.decision_id,
        "session_id": created.session_uuid.to_string(),
        "status": created.status,
    })
    .to_string();
    let _ = emit_audit_critical(
        state,
        AuditEvent::new(AuditEventType::McpContestationOpened, details)
            .session(created.session_uuid.to_string()),
    )
    .await;

    Ok(created)
}

/// Claim an open contestation for review (SoD).
pub async fn claim_contestation(
    state: &AppState,
    contestation_uuid: Uuid,
    actor_user_id: i32,
) -> AppResult<AccessContestation> {
    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {e}")))?;

    let row: AccessContestation = access_contestations::table
        .filter(access_contestations::uuid.eq(contestation_uuid))
        .first(&mut conn)
        .await
        .map_err(|e| match e {
            diesel::result::Error::NotFound => AppError::NotFound("Contestation not found".into()),
            other => AppError::Database(other),
        })?;

    if row.opened_by_id == actor_user_id {
        return Err(AppError::Authorization(
            "You cannot review a contestation you opened (separation of duties)".into(),
        ));
    }
    if row.status != STATUS_OPEN {
        return Err(AppError::Validation(
            "Only open contestations can be claimed".into(),
        ));
    }

    let now = Utc::now();
    let updated: AccessContestation =
        diesel::update(access_contestations::table.filter(access_contestations::id.eq(row.id)))
            .set((
                access_contestations::status.eq(STATUS_UNDER_REVIEW),
                access_contestations::claimed_by_id.eq(actor_user_id),
                access_contestations::claimed_at.eq(now),
            ))
            .get_result(&mut conn)
            .await
            .map_err(AppError::Database)?;

    Ok(updated)
}

/// Uphold the original access decision (confirm the cut).
pub async fn uphold_contestation(
    state: &AppState,
    contestation_uuid: Uuid,
    actor_user_id: i32,
    note: &str,
) -> AppResult<AccessContestation> {
    resolve(
        state,
        contestation_uuid,
        actor_user_id,
        STATUS_UPHELD,
        note,
        None,
    )
    .await
}

/// Overturn: restore the **same** group that caused the IAM suspension
/// (1:1). `restore_group_id` must match the session's stamped source
/// (or the unique heuristic when stamp is missing).
pub async fn overturn_contestation(
    state: &AppState,
    contestation_uuid: Uuid,
    actor_user_id: i32,
    note: &str,
) -> AppResult<AccessContestation> {
    let row = get_by_uuid(state, contestation_uuid).await?;
    let session = load_session_by_uuid(state, row.session_uuid).await?;
    let (restore_group_id, _) = resolve_restore_group_for_session(state, &session).await?;

    let updated = resolve(
        state,
        contestation_uuid,
        actor_user_id,
        STATUS_OVERTURNED,
        note,
        Some(restore_group_id),
    )
    .await?;

    // Re-eligibility only — never resurrect the old session ticket.
    if let Err(e) = state
        .access_client
        .add_group_member(restore_group_id, updated.subject_user_id)
        .await
    {
        tracing::error!(
            contestation = %updated.uuid,
            group_id = restore_group_id,
            user_id = updated.subject_user_id,
            error = %e,
            "R1 overturn: AddGroupMember failed after status write"
        );
        return Err(AppError::Internal(anyhow::anyhow!(
            "Contestation marked overturned but group restore failed: {e}"
        )));
    }
    crate::services::mcp_recheck::notify_policy_changed(state).await;

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {e}")))?;
    let now = Utc::now();
    let final_row: AccessContestation =
        diesel::update(access_contestations::table.filter(access_contestations::id.eq(updated.id)))
            .set(access_contestations::restore_applied_at.eq(now))
            .get_result(&mut conn)
            .await
            .map_err(AppError::Database)?;

    Ok(final_row)
}

async fn resolve(
    state: &AppState,
    contestation_uuid: Uuid,
    actor_user_id: i32,
    new_status: &str,
    note: &str,
    restore_group_id: Option<i32>,
) -> AppResult<AccessContestation> {
    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {e}")))?;

    let row: AccessContestation = access_contestations::table
        .filter(access_contestations::uuid.eq(contestation_uuid))
        .first(&mut conn)
        .await
        .map_err(|e| match e {
            diesel::result::Error::NotFound => AppError::NotFound("Contestation not found".into()),
            other => AppError::Database(other),
        })?;

    if row.opened_by_id == actor_user_id {
        return Err(AppError::Authorization(
            "You cannot resolve a contestation you opened (separation of duties)".into(),
        ));
    }
    if !row.is_open_queue() {
        return Err(AppError::Validation(
            "This contestation is already resolved".into(),
        ));
    }
    if new_status == STATUS_OVERTURNED {
        let Some(gid) = restore_group_id else {
            return Err(AppError::Validation(
                "Overturn requires a group to restore membership into".into(),
            ));
        };
        let group_ok: bool = vauban_groups::table
            .filter(vauban_groups::id.eq(gid))
            .select(vauban_groups::id)
            .first::<i32>(&mut conn)
            .await
            .optional()
            .map_err(AppError::Database)?
            .is_some();
        if !group_ok {
            return Err(AppError::Validation("Restore group not found".into()));
        }
        let subject_ok: (bool, bool) = users::table
            .filter(users::id.eq(row.subject_user_id))
            .select((users::is_active, users::is_deleted))
            .first(&mut conn)
            .await
            .map_err(AppError::Database)?;
        if subject_ok.1 || !subject_ok.0 {
            return Err(AppError::Validation(
                "Subject account is inactive or deleted — cannot restore group membership".into(),
            ));
        }
    }

    let now = Utc::now();
    let note_trim = {
        let t = note.trim();
        if t.is_empty() {
            None
        } else {
            Some(t.to_string())
        }
    };

    // Auto-claim if still open.
    let claimed_by = row.claimed_by_id.or(Some(actor_user_id));
    let claimed_at = row.claimed_at.or(Some(now));

    let updated: AccessContestation =
        diesel::update(access_contestations::table.filter(access_contestations::id.eq(row.id)))
            .set((
                access_contestations::status.eq(new_status),
                access_contestations::claimed_by_id.eq(claimed_by),
                access_contestations::claimed_at.eq(claimed_at),
                access_contestations::resolved_by_id.eq(actor_user_id),
                access_contestations::resolved_at.eq(now),
                access_contestations::resolution_note.eq(note_trim),
                access_contestations::restore_group_id.eq(restore_group_id),
            ))
            .get_result(&mut conn)
            .await
            .map_err(AppError::Database)?;

    drop(conn);

    let details = serde_json::json!({
        "contestation_id": updated.uuid.to_string(),
        "decision_id": updated.decision_id,
        "session_id": updated.session_uuid.to_string(),
        "status": updated.status,
        "restore_group_id": updated.restore_group_id,
    })
    .to_string();
    let _ = emit_audit_critical(
        state,
        AuditEvent::new(AuditEventType::McpContestationResolved, details)
            .session(updated.session_uuid.to_string()),
    )
    .await;

    Ok(updated)
}

/// Load session by uuid for contest open.
pub async fn load_session_by_uuid(state: &AppState, session_uuid: Uuid) -> AppResult<ProxySession> {
    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {e}")))?;
    proxy_sessions::table
        .filter(proxy_sessions::uuid.eq(session_uuid))
        .first(&mut conn)
        .await
        .map_err(|e| match e {
            diesel::result::Error::NotFound => AppError::NotFound("Session not found".into()),
            other => AppError::Database(other),
        })
}

pub async fn get_by_uuid(
    state: &AppState,
    contestation_uuid: Uuid,
) -> AppResult<AccessContestation> {
    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {e}")))?;
    access_contestations::table
        .filter(access_contestations::uuid.eq(contestation_uuid))
        .first(&mut conn)
        .await
        .map_err(|e| match e {
            diesel::result::Error::NotFound => AppError::NotFound("Contestation not found".into()),
            other => AppError::Database(other),
        })
}

/// Open + under_review first, then recent resolved (cap 100).
pub async fn list_recent(state: &AppState) -> AppResult<Vec<AccessContestation>> {
    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {e}")))?;
    access_contestations::table
        .order(access_contestations::opened_at.desc())
        .limit(100)
        .load(&mut conn)
        .await
        .map_err(AppError::Database)
}

/// Count open-queue items not opened by `exclude_opener_id` (SoD-aware badge).
pub async fn count_reviewable(state: &AppState, exclude_opener_id: Option<i32>) -> AppResult<i64> {
    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {e}")))?;
    let mut q = access_contestations::table
        .filter(access_contestations::status.eq_any([STATUS_OPEN, STATUS_UNDER_REVIEW]))
        .into_boxed();
    if let Some(oid) = exclude_opener_id {
        q = q.filter(access_contestations::opened_by_id.ne(oid));
    }
    q.count()
        .get_result(&mut conn)
        .await
        .map_err(AppError::Database)
}

pub async fn find_open_for_decision(
    state: &AppState,
    decision_id: &str,
) -> AppResult<Option<AccessContestation>> {
    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {e}")))?;
    access_contestations::table
        .filter(access_contestations::decision_id.eq(decision_id))
        .filter(access_contestations::status.eq_any([STATUS_OPEN, STATUS_UNDER_REVIEW]))
        .first(&mut conn)
        .await
        .optional()
        .map_err(AppError::Database)
}

/// Resolve the unique restore group for an IAM-suspension overturn (1:1).
/// Prefer `decision_source_group_id` (stamped on group remove); else a
/// single MCP rule group the subject is not in. Ambiguous / missing → err.
pub async fn resolve_restore_group_for_session(
    state: &AppState,
    session: &ProxySession,
) -> AppResult<(i32, String)> {
    use crate::schema::{access_rules, asset_asset_groups, user_groups};

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {e}")))?;

    // First Mission Seal drift only stamps a source group when IAM was
    // `suspend_group`. Do not invent AddGroupMember for terminate / key /
    // tombstone via the heuristic.
    if session.termination_reason.as_deref() == Some("mandate_drift")
        && session.decision_source_group_id.is_none()
    {
        return Err(AppError::Validation(
            "Overturn is only available when Mission Seal drift used suspend group \
             (IAM). Uphold instead, or restore access manually."
                .into(),
        ));
    }

    if let Some(gid) = session.decision_source_group_id {
        let name: Option<String> = vauban_groups::table
            .filter(vauban_groups::id.eq(gid))
            .select(vauban_groups::name)
            .first::<String>(&mut conn)
            .await
            .optional()
            .map_err(AppError::Database)?;
        if let Some(name) = name {
            return Ok((gid, name));
        }
    }

    let rule_group_ids: Vec<i32> = access_rules::table
        .inner_join(
            asset_asset_groups::table
                .on(asset_asset_groups::asset_group_id.eq(access_rules::asset_group_id)),
        )
        .filter(asset_asset_groups::asset_id.eq(session.asset_id))
        .filter(access_rules::is_active.eq(true))
        .filter(access_rules::allowed_protocols.contains(vec![Some("mcp".to_string())]))
        .select(access_rules::user_group_id)
        .distinct()
        .load::<i32>(&mut conn)
        .await
        .unwrap_or_default();

    let member_of: Vec<i32> = user_groups::table
        .filter(user_groups::user_id.eq(session.user_id))
        .select(user_groups::group_id)
        .load::<i32>(&mut conn)
        .await
        .unwrap_or_default();

    let heuristic: Vec<i32> = rule_group_ids
        .into_iter()
        .filter(|gid| !member_of.contains(gid))
        .collect();

    match heuristic.as_slice() {
        [only] => {
            let name: String = vauban_groups::table
                .filter(vauban_groups::id.eq(*only))
                .select(vauban_groups::name)
                .first(&mut conn)
                .await
                .map_err(AppError::Database)?;
            Ok((*only, name))
        }
        [] => Err(AppError::Validation(
            "Overturn is only available when the cut is linked to a removed access group \
             (IAM suspension). Uphold instead, or re-add the user to a group manually."
                .into(),
        )),
        _ => Err(AppError::Validation(
            "Overturn cannot choose automatically: several access groups could restore this \
             session. Re-add the subject to the correct group manually, or uphold."
                .into(),
        )),
    }
}

pub async fn resolve_user_db_id(state: &AppState, user_uuid: &str) -> AppResult<i32> {
    let uid =
        Uuid::parse_str(user_uuid).map_err(|_| AppError::Validation("Invalid user uuid".into()))?;
    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {e}")))?;
    users::table
        .filter(users::uuid.eq(uid))
        .select(users::id)
        .first(&mut conn)
        .await
        .map_err(|e| match e {
            diesel::result::Error::NotFound => AppError::NotFound("User not found".into()),
            other => AppError::Database(other),
        })
}

pub async fn username_for_id(state: &AppState, user_id: i32) -> String {
    let Ok(mut conn) = state.db_pool.get().await else {
        return format!("user#{user_id}");
    };
    users::table
        .filter(users::id.eq(user_id))
        .select(users::username)
        .first::<String>(&mut conn)
        .await
        .unwrap_or_else(|_| format!("user#{user_id}"))
}

#[cfg(test)]
mod tests {
    #[test]
    fn sod_constants_and_status_vocab() {
        use super::*;
        assert_eq!(STATUS_OPEN, "open");
        assert_eq!(STATUS_UNDER_REVIEW, "under_review");
        assert_eq!(STATUS_UPHELD, "upheld");
        assert_eq!(STATUS_OVERTURNED, "overturned");
        assert_eq!(OPEN_REASON_MIN, 10);
        assert_eq!(OPEN_REASON_MAX, 1000);
    }
}
