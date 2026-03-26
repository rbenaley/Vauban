/// VAUBAN Web - Asset access service.
///
/// Determines which assets a user can see and connect to, based on
/// access rules linking user groups to asset groups.
///
/// When `access_client` is Some, access checks are delegated to vauban-access
/// via IPC. When None, falls back to direct SQL queries.
use chrono::Utc;
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
    pub require_justification: bool,
    pub max_session_duration: Option<i32>,
}

impl AccessCheckResult {
    pub fn denied() -> Self {
        Self {
            allowed: false,
            require_mfa: false,
            require_justification: false,
            max_session_duration: None,
        }
    }
}

/// Return the IDs of all assets accessible to a given user via active,
/// temporally valid access rules.
///
/// The query walks: user -> user_groups -> access_rules -> asset_groups -> assets.
/// Only non-deleted assets with active, temporally valid rules are returned.
/// Assets are filtered by protocol: the asset's `asset_type` must appear in the
/// rule's `allowed_protocols` array.
///
/// When `access_client` is Some, delegates to vauban-access via IPC and resolves
/// asset IDs from local DB. On IPC error, returns empty Vec (fail-closed).
pub async fn list_accessible_asset_ids(
    access_client: Option<&Arc<AccessIpcClient>>,
    conn: &mut AsyncPgConnection,
    user_id: i32,
) -> Result<Vec<i32>, AppError> {
    if let Some(client) = access_client {
        return list_accessible_asset_ids_ipc(client, conn, user_id).await;
    }
    list_accessible_asset_ids_sql(conn, user_id).await
}

async fn list_accessible_asset_ids_ipc(
    client: &AccessIpcClient,
    conn: &mut AsyncPgConnection,
    user_id: i32,
) -> Result<Vec<i32>, AppError> {
    use crate::schema::{asset_asset_groups, assets};

    let entries = match client.list_accessible_groups(user_id).await {
        Ok(e) => e,
        Err(_) => return Ok(Vec::new()), // fail-closed
    };

    let mut all_ids = Vec::new();
    for entry in entries {
        if entry.protocols.is_empty() {
            continue;
        }
        let ids: Vec<i32> = assets::table
            .inner_join(
                asset_asset_groups::table.on(assets::id.eq(asset_asset_groups::asset_id)),
            )
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

async fn list_accessible_asset_ids_sql(
    conn: &mut AsyncPgConnection,
    user_id: i32,
) -> Result<Vec<i32>, AppError> {
    use crate::schema::{access_rules, asset_asset_groups, asset_groups, assets, user_groups};

    let now = Utc::now();

    #[allow(deprecated)]
    let ids: Vec<i32> = assets::table
        .inner_join(
            asset_asset_groups::table.on(assets::id.eq(asset_asset_groups::asset_id)),
        )
        .inner_join(
            asset_groups::table.on(asset_asset_groups::asset_group_id.eq(asset_groups::id)),
        )
        .inner_join(access_rules::table.on(access_rules::asset_group_id.eq(asset_groups::id)))
        .inner_join(user_groups::table.on(user_groups::group_id.eq(access_rules::user_group_id)))
        .filter(user_groups::user_id.eq(user_id))
        .filter(access_rules::is_active.eq(true))
        .filter(assets::is_deleted.eq(false))
        .filter(
            assets::asset_type
                .nullable()
                .eq(diesel::pg::expression::dsl::any(
                    access_rules::allowed_protocols,
                )),
        )
        .filter(
            access_rules::valid_from
                .is_null()
                .or(access_rules::valid_from.le(now)),
        )
        .filter(
            access_rules::valid_until
                .is_null()
                .or(access_rules::valid_until.ge(now)),
        )
        .select(assets::id)
        .distinct()
        .load(conn)
        .await
        .map_err(AppError::Database)?;

    Ok(ids)
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
/// When `access_client` is Some, delegates to vauban-access via IPC. On IPC
/// error, returns denied (fail-closed).
pub async fn can_access_asset(
    access_client: Option<&Arc<AccessIpcClient>>,
    conn: &mut AsyncPgConnection,
    user_id: i32,
    asset_id: i32,
    protocol: &str,
) -> Result<AccessCheckResult, AppError> {
    if let Some(client) = access_client {
        return can_access_asset_ipc(client, conn, user_id, asset_id, protocol).await;
    }
    can_access_asset_sql(conn, user_id, asset_id, protocol).await
}

async fn can_access_asset_ipc(
    client: &AccessIpcClient,
    conn: &mut AsyncPgConnection,
    user_id: i32,
    asset_id: i32,
    protocol: &str,
) -> Result<AccessCheckResult, AppError> {
    use crate::schema::{asset_asset_groups, assets};

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

    let asset_group_ids: Vec<i32> = asset_asset_groups::table
        .filter(asset_asset_groups::asset_id.eq(asset_id))
        .select(asset_asset_groups::asset_group_id)
        .load(conn)
        .await
        .map_err(AppError::Database)?;

    if asset_group_ids.is_empty() {
        return Ok(AccessCheckResult::denied());
    }

    let mut allowed = false;
    let mut require_mfa = false;
    let mut require_justification = false;
    let mut max_session_duration: Option<i32> = None;

    for gid in asset_group_ids {
        let ipc_result = match client.check_access(user_id, gid, protocol).await {
            Ok(r) => r,
            Err(_) => continue,
        };
        if ipc_result.allowed {
            allowed = true;
            if ipc_result.require_mfa {
                require_mfa = true;
            }
            if ipc_result.require_justification {
                require_justification = true;
            }
            if let Some(d) = ipc_result.max_session_duration {
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
        require_justification,
        max_session_duration,
    })
}

async fn can_access_asset_sql(
    conn: &mut AsyncPgConnection,
    user_id: i32,
    asset_id: i32,
    protocol: &str,
) -> Result<AccessCheckResult, AppError> {
    use crate::schema::{access_rules, asset_asset_groups, assets, user_groups};

    let now = Utc::now();

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

    let asset_group_ids: Vec<i32> = asset_asset_groups::table
        .filter(asset_asset_groups::asset_id.eq(asset_id))
        .select(asset_asset_groups::asset_group_id)
        .load(conn)
        .await
        .map_err(AppError::Database)?;

    if asset_group_ids.is_empty() {
        return Ok(AccessCheckResult::denied());
    }

    #[allow(clippy::type_complexity)]
    let matching_rules: Vec<(bool, bool, Option<i32>)> = access_rules::table
        .inner_join(user_groups::table.on(user_groups::group_id.eq(access_rules::user_group_id)))
        .filter(user_groups::user_id.eq(user_id))
        .filter(access_rules::asset_group_id.eq_any(asset_group_ids))
        .filter(access_rules::is_active.eq(true))
        .filter(
            access_rules::valid_from
                .is_null()
                .or(access_rules::valid_from.le(now)),
        )
        .filter(
            access_rules::valid_until
                .is_null()
                .or(access_rules::valid_until.ge(now)),
        )
        .select((
            access_rules::require_mfa,
            access_rules::require_justification,
            access_rules::max_session_duration,
        ))
        .filter(access_rules::allowed_protocols.contains(vec![Some(protocol.to_string())]))
        .load(conn)
        .await
        .map_err(AppError::Database)?;

    if matching_rules.is_empty() {
        return Ok(AccessCheckResult::denied());
    }

    let require_mfa = matching_rules.iter().any(|(mfa, _, _)| *mfa);
    let require_justification = matching_rules.iter().any(|(_, just, _)| *just);
    let max_session_duration = matching_rules.iter().filter_map(|(_, _, dur)| *dur).min();

    Ok(AccessCheckResult {
        allowed: true,
        require_mfa,
        require_justification,
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
        assert!(!result.require_justification);
        assert!(result.max_session_duration.is_none());
    }

    #[test]
    fn test_access_check_result_debug() {
        let result = AccessCheckResult {
            allowed: true,
            require_mfa: true,
            require_justification: false,
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
            require_justification: true,
            max_session_duration: Some(7200),
        };
        let cloned = result.clone();
        assert_eq!(cloned.allowed, result.allowed);
        assert_eq!(cloned.require_mfa, result.require_mfa);
        assert_eq!(cloned.require_justification, result.require_justification);
        assert_eq!(cloned.max_session_duration, result.max_session_duration);
    }
}
