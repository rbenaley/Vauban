//! Erase MCP tool names that left the approved catalogue from access rules.
//!
//! vauban-access owns the rewrite (`AccessRequest::PruneMcpRuleTools`); web
//! only says which asset groups changed. Call [`prune_after_change`] after
//! every write that can shrink the approved set of an asset group: asset
//! delete, asset edit, asset group membership change, Discover, Approve and
//! drift quarantine. The proxy still intersects with the live catalogue at
//! session open, so a failed prune never grants a tool.

use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};

use crate::AppState;
use crate::schema::asset_asset_groups;

/// Asset groups `asset_id` belongs to. Read it before a delete or a regroup.
pub async fn asset_group_ids_of(
    conn: &mut AsyncPgConnection,
    asset_id: i32,
) -> QueryResult<Vec<i32>> {
    asset_asset_groups::table
        .filter(asset_asset_groups::asset_id.eq(asset_id))
        .select(asset_asset_groups::asset_group_id)
        .load::<i32>(conn)
        .await
}

/// Prune scope for a change on `groups`: those groups plus the virtual
/// « All assets » group, whose approved set is every live MCP asset.
pub fn scope_with_virtual(mut groups: Vec<i32>) -> Vec<i32> {
    let virtual_id = crate::services::virtual_group::virtual_asset_group_id();
    if virtual_id != crate::services::virtual_group::UNINITIALIZED_VIRTUAL_ID {
        groups.push(virtual_id);
    }
    groups.sort_unstable();
    groups.dedup();
    groups
}

/// Best-effort prune of the rules on `groups` (plus the virtual group).
pub async fn prune_after_change(state: &AppState, groups: Vec<i32>, reason: &'static str) {
    let scope = scope_with_virtual(groups);
    if scope.is_empty() {
        return;
    }
    match state
        .access_client
        .prune_mcp_rule_tools(Some(scope.clone()))
        .await
    {
        Ok(rules_changed) => {
            if rules_changed > 0 {
                tracing::info!(reason, ?scope, rules_changed, "MCP rule tools pruned");
            }
        }
        Err(e) => tracing::error!(
            reason,
            ?scope,
            error = %e,
            "MCP rule tools prune failed; leftover names stay inert until the next prune"
        ),
    }
}

/// [`prune_after_change`] for one asset: its current groups.
pub async fn prune_after_asset_change(
    state: &AppState,
    conn: &mut AsyncPgConnection,
    asset_id: i32,
    reason: &'static str,
) {
    match asset_group_ids_of(conn, asset_id).await {
        Ok(groups) => prune_after_change(state, groups, reason).await,
        Err(e) => tracing::error!(
            reason,
            asset_id,
            error = %e,
            "MCP rule tools prune skipped: asset groups lookup failed; leftover names stay inert until the next prune"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_is_sorted_deduped_and_never_widens_to_every_rule() {
        let got = scope_with_virtual(vec![3, 1, 3]);
        assert!(got.contains(&1) && got.contains(&3));
        assert!(got.windows(2).all(|w| w[0] < w[1]));
        let virtual_id = crate::services::virtual_group::virtual_asset_group_id();
        if virtual_id == crate::services::virtual_group::UNINITIALIZED_VIRTUAL_ID {
            assert_eq!(got, vec![1, 3]);
            assert!(scope_with_virtual(Vec::new()).is_empty());
        } else {
            assert!(got.contains(&virtual_id));
        }
    }
}
