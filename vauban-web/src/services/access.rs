/// VAUBAN Web - Asset access service.
///
/// Determines which assets a user can see and connect to, based on
/// access rules linking user groups to asset groups.
///
/// All decisions are delegated to vauban-access via IPC; vauban-web does not
/// run in standalone mode and therefore carries no SQL fallback.
use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use std::sync::Arc;

use crate::error::AppError;
use crate::ipc::AccessIpcClient;

/// Result of an access check with additional constraint metadata.
#[derive(Debug, Clone)]
pub struct AccessCheckResult {
    pub allowed: bool,
    pub require_mfa: bool,
    pub require_approval: bool,
    pub max_session_duration: Option<i32>,
}

impl AccessCheckResult {
    pub fn denied() -> Self {
        Self {
            allowed: false,
            require_mfa: false,
            require_approval: false,
            max_session_duration: None,
        }
    }
}

/// Return the IDs of all assets accessible to a given user via active,
/// temporally valid access rules.
///
/// The IPC service computes the set of (asset_group_id, protocols) accessible
/// to the user; local DB is only used to resolve those groups to asset IDs
/// and filter deleted rows / protocol mismatches.
///
/// Fail-closed: returns an empty Vec on IPC error.
pub async fn list_accessible_asset_ids(
    access_client: &Arc<AccessIpcClient>,
    conn: &mut AsyncPgConnection,
    user_id: i32,
) -> Result<Vec<i32>, AppError> {
    use crate::schema::{asset_asset_groups, assets};

    let entries = match access_client.list_accessible_groups(user_id).await {
        Ok(e) => e,
        Err(err) => {
            tracing::error!(
                user_id, error = %err,
                "list_accessible_groups IPC call failed; returning empty set (fail-closed)"
            );
            return Ok(Vec::new());
        }
    };

    let virtual_id = crate::services::virtual_group::virtual_asset_group_id();
    let mut all_ids = Vec::new();
    for entry in entries {
        if entry.protocols.is_empty() {
            continue;
        }
        // Special-case the virtual "All assets" group: instead of joining
        // through `asset_asset_groups` (which has zero rows for the
        // virtual id, by trigger invariant), enumerate every non-deleted
        // asset that matches one of the rule's allowed protocols. Same
        // soft-delete and protocol semantics as a static rule, just with
        // a dynamic membership.
        if entry.asset_group_id == virtual_id {
            let ids: Vec<i32> = assets::table
                .filter(assets::is_deleted.eq(false))
                .filter(assets::asset_type.eq_any(&entry.protocols))
                .select(assets::id)
                .load(conn)
                .await
                .map_err(AppError::Database)?;
            all_ids.extend(ids);
            continue;
        }
        let ids: Vec<i32> = assets::table
            .inner_join(asset_asset_groups::table.on(assets::id.eq(asset_asset_groups::asset_id)))
            .filter(asset_asset_groups::asset_group_id.eq(entry.asset_group_id))
            .filter(assets::is_deleted.eq(false))
            .filter(assets::asset_type.eq_any(&entry.protocols))
            .select(assets::id)
            .load(conn)
            .await
            .map_err(AppError::Database)?;
        all_ids.extend(ids);
    }
    all_ids.sort_unstable();
    all_ids.dedup();
    Ok(all_ids)
}

/// Check whether a user can access a specific asset for a given protocol.
///
/// Returns an `AccessCheckResult` containing the decision and any constraints
/// (MFA requirement, justification requirement, max duration) that the caller
/// must enforce.
///
/// When multiple rules match, the most permissive result wins (any-allow),
/// but MFA/justification requirements are ORed (if any matching rule requires
/// them, the caller must enforce them).
///
/// Always delegates to vauban-access via IPC (no fallback). On IPC error,
/// returns denied (fail-closed).
pub async fn can_access_asset(
    access_client: &Arc<AccessIpcClient>,
    conn: &mut AsyncPgConnection,
    user_id: i32,
    asset_id: i32,
    protocol: &str,
) -> Result<AccessCheckResult, AppError> {
    use crate::schema::{asset_asset_groups, assets};
    let client = access_client.as_ref();

    let _: i32 = assets::table
        .filter(assets::id.eq(asset_id))
        .filter(assets::is_deleted.eq(false))
        .select(assets::id)
        .first(conn)
        .await
        .map_err(|e| match e {
            diesel::result::Error::NotFound => AppError::NotFound("Asset not found".to_string()),
            _ => AppError::Database(e),
        })?;

    let mut asset_group_ids: Vec<i32> = asset_asset_groups::table
        .filter(asset_asset_groups::asset_id.eq(asset_id))
        .select(asset_asset_groups::asset_group_id)
        .load(conn)
        .await
        .map_err(AppError::Database)?;

    // Defense-in-depth: always include the virtual "All assets" id so a
    // rule on the virtual group is considered even for orphan assets
    // (those that belong to no static group). vauban-access also adds
    // the virtual id symmetrically in `handle_check_access_by_uuid`, so
    // the proxy-side AccessGuard re-check stays in lock-step.
    let virtual_id = crate::services::virtual_group::virtual_asset_group_id();
    if !asset_group_ids.contains(&virtual_id) {
        asset_group_ids.push(virtual_id);
    }

    if asset_group_ids.is_empty() {
        return Ok(AccessCheckResult::denied());
    }

    let entries = client
        .check_access_multi(user_id, &asset_group_ids, protocol)
        .await?;

    let mut allowed = false;
    let mut require_mfa = false;
    let mut require_approval = false;
    let mut max_session_duration: Option<i32> = None;

    for entry in entries {
        if entry.result.allowed {
            allowed = true;
            if entry.result.require_mfa {
                require_mfa = true;
            }
            if entry.result.require_approval {
                require_approval = true;
            }
            if let Some(d) = entry.result.max_session_duration {
                max_session_duration = Some(match max_session_duration {
                    None => d,
                    Some(cur) => cur.min(d),
                });
            }
        }
    }

    if !allowed {
        return Ok(AccessCheckResult::denied());
    }

    Ok(AccessCheckResult {
        allowed: true,
        require_mfa,
        require_approval,
        max_session_duration,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_access_check_result_denied() {
        let result = AccessCheckResult::denied();
        assert!(!result.allowed);
        assert!(!result.require_mfa);
        assert!(!result.require_approval);
        assert!(result.max_session_duration.is_none());
    }

    #[test]
    fn test_access_check_result_debug() {
        let result = AccessCheckResult {
            allowed: true,
            require_mfa: true,
            require_approval: false,
            max_session_duration: Some(3600),
        };
        let debug = format!("{:?}", result);
        assert!(debug.contains("allowed: true"));
        assert!(debug.contains("require_mfa: true"));
        assert!(debug.contains("3600"));
    }

    #[test]
    fn test_access_check_result_clone() {
        let result = AccessCheckResult {
            allowed: true,
            require_mfa: true,
            require_approval: true,
            max_session_duration: Some(7200),
        };
        let cloned = result.clone();
        assert_eq!(cloned.allowed, result.allowed);
        assert_eq!(cloned.require_mfa, result.require_mfa);
        assert_eq!(cloned.require_approval, result.require_approval);
        assert_eq!(cloned.max_session_duration, result.max_session_duration);
    }
}
