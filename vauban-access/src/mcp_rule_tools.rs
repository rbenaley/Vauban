//! MCP tool names on access rules: approved names only.
//!
//! An access rule's `mcp_allowed_tools`, `mcp_hitl_tools` and
//! `mcp_require_plan_tools` may only name tools approved on a live MCP
//! asset of the rule's asset group (virtual « All assets » = every live
//! MCP asset). Writes that name anything else are refused as a whole, and
//! [`prune_mcp_rule_tools`] erases names that left the approved catalogue
//! (asset deleted, asset out of the group, tool quarantined).
//!
//! Writers and the prune serialise on one transaction-scoped advisory
//! lock, so a rule update validated against the old catalogue cannot land
//! after the prune that follows a catalogue change.

use std::collections::BTreeSet;

use diesel::prelude::*;
use diesel::sql_types::BigInt;
use diesel_async::RunQueryDsl;
use shared::mcp_policy::{
    McpRuleToolColumns, RULE_TOOLS_NOT_APPROVED, prune_rule_tools, rule_tools_outside,
};
use tracing::{info, warn};
use uuid::Uuid;

use crate::db::DbConnection;
use crate::schema::{access_rules, asset_asset_groups, assets};

/// `pg_advisory_xact_lock` key shared by rule writes and the prune ("VBMCRULE").
const RULE_TOOLS_LOCK_KEY: i64 = 0x5642_4D43_5255_4C45;

/// Takes the rule-tools advisory lock until the end of the current transaction.
pub async fn lock_rule_tools(conn: &mut DbConnection) -> QueryResult<()> {
    diesel::sql_query("SELECT pg_advisory_xact_lock($1)")
        .bind::<BigInt, _>(RULE_TOOLS_LOCK_KEY)
        .execute(conn)
        .await
        .map(|_| ())
}

fn approved_from_configs(configs: Vec<serde_json::Value>) -> BTreeSet<String> {
    configs
        .iter()
        .filter_map(|cfg| cfg.get("allowed_tools"))
        .filter_map(|v| serde_json::from_value::<Vec<String>>(v.clone()).ok())
        .flatten()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Approved tool names of every live MCP asset in `asset_group_id`.
pub async fn approved_mcp_names_for_group(
    conn: &mut DbConnection,
    asset_group_id: i32,
) -> QueryResult<BTreeSet<String>> {
    let virtual_id = crate::virtual_group::virtual_asset_group_id();
    let configs: Vec<serde_json::Value> = if virtual_id
        != crate::virtual_group::UNINITIALIZED_VIRTUAL_ID
        && asset_group_id == virtual_id
    {
        assets::table
            .filter(assets::is_deleted.eq(false))
            .filter(assets::asset_type.eq("mcp"))
            .select(assets::connection_config)
            .load(conn)
            .await?
    } else {
        assets::table
            .inner_join(asset_asset_groups::table.on(asset_asset_groups::asset_id.eq(assets::id)))
            .filter(asset_asset_groups::asset_group_id.eq(asset_group_id))
            .filter(assets::is_deleted.eq(false))
            .filter(assets::asset_type.eq("mcp"))
            .select(assets::connection_config)
            .load(conn)
            .await?
    };
    Ok(approved_from_configs(configs))
}

/// Why a rule write was refused.
#[derive(Debug)]
pub enum RuleToolsError {
    NotApproved(BTreeSet<String>),
    Db(diesel::result::Error),
}

impl From<diesel::result::Error> for RuleToolsError {
    fn from(e: diesel::result::Error) -> Self {
        Self::Db(e)
    }
}

impl std::fmt::Display for RuleToolsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotApproved(names) => write!(
                f,
                "{RULE_TOOLS_NOT_APPROVED}: {}",
                names.iter().cloned().collect::<Vec<_>>().join(", ")
            ),
            Self::Db(e) => write!(f, "{e}"),
        }
    }
}

/// Refuses `cols` if any name is not approved on `asset_group_id`.
/// Call inside the write transaction, after [`lock_rule_tools`].
pub async fn validate_rule_tools(
    conn: &mut DbConnection,
    asset_group_id: i32,
    cols: &McpRuleToolColumns,
) -> Result<(), RuleToolsError> {
    let (allow, hitl, plan) = cols;
    if allow.is_none() && hitl.is_none() && plan.is_none() {
        return Ok(());
    }
    let approved = approved_mcp_names_for_group(conn, asset_group_id).await?;
    let outside = rule_tools_outside(cols, &approved);
    if outside.is_empty() {
        Ok(())
    } else {
        Err(RuleToolsError::NotApproved(outside))
    }
}

type RuleToolsRow = (
    i32,
    Uuid,
    i32,
    Option<Vec<Option<String>>>,
    Option<Vec<Option<String>>>,
    Option<Vec<Option<String>>>,
);

/// Rewrites the tool columns of every rule that names a tool, keeping only
/// names approved on its asset group. `scope` limits the pass to rules on
/// those asset groups (`None` = every rule). Returns the number of rules changed.
pub async fn prune_mcp_rule_tools(
    conn: &mut DbConnection,
    scope: Option<&[i32]>,
) -> QueryResult<u32> {
    use diesel_async::AsyncConnection;
    use diesel_async::scoped_futures::ScopedFutureExt;

    conn.transaction::<u32, diesel::result::Error, _>(|conn| {
        async move {
            lock_rule_tools(conn).await?;
            let mut query = access_rules::table
                .filter(
                    access_rules::mcp_allowed_tools
                        .is_not_null()
                        .or(access_rules::mcp_hitl_tools.is_not_null())
                        .or(access_rules::mcp_require_plan_tools.is_not_null()),
                )
                .select((
                    access_rules::id,
                    access_rules::uuid,
                    access_rules::asset_group_id,
                    access_rules::mcp_allowed_tools,
                    access_rules::mcp_hitl_tools,
                    access_rules::mcp_require_plan_tools,
                ))
                .into_boxed();
            if let Some(groups) = scope {
                query = query.filter(access_rules::asset_group_id.eq_any(groups.to_vec()));
            }
            let rows: Vec<RuleToolsRow> = query.load(conn).await?;

            let mut approved_by_group: std::collections::HashMap<i32, BTreeSet<String>> =
                std::collections::HashMap::new();
            let mut changed = 0u32;
            for (id, uuid, group_id, allow, hitl, plan) in rows {
                let approved = match approved_by_group.get(&group_id) {
                    Some(set) => set.clone(),
                    None => {
                        let set = approved_mcp_names_for_group(conn, group_id).await?;
                        approved_by_group.insert(group_id, set.clone());
                        set
                    }
                };
                let cols: McpRuleToolColumns = (allow, hitl, plan);
                let removed = rule_tools_outside(&cols, &approved);
                let pruned = prune_rule_tools(cols.clone(), &approved);
                if pruned == cols {
                    continue;
                }
                let (allow, hitl, plan) = pruned;
                diesel::update(access_rules::table.filter(access_rules::id.eq(id)))
                    .set((
                        access_rules::mcp_allowed_tools.eq(allow),
                        access_rules::mcp_hitl_tools.eq(hitl),
                        access_rules::mcp_require_plan_tools.eq(plan),
                        access_rules::updated_at.eq(chrono::Utc::now()),
                    ))
                    .execute(conn)
                    .await?;
                changed = changed.saturating_add(1);
                info!(
                    rule = %uuid,
                    asset_group_id = group_id,
                    removed = ?removed,
                    "MCP rule tools pruned: names no longer approved on the asset group"
                );
            }
            Ok(changed)
        }
        .scope_boxed()
    })
    .await
}

/// Boot pass: clears names left by assets deleted or tools quarantined
/// before this version. Never fails the boot.
pub async fn prune_at_boot(pool: &crate::db::DbPool) {
    let mut conn = match pool.get().await {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "MCP rule tools boot prune skipped: no DB connection");
            return;
        }
    };
    match prune_mcp_rule_tools(&mut conn, None).await {
        Ok(n) => info!(rules_changed = n, "MCP rule tools boot prune done"),
        Err(e) => warn!(error = %e, "MCP rule tools boot prune failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approved_from_configs_reads_allowed_tools_only() {
        let got = approved_from_configs(vec![
            serde_json::json!({"allowed_tools": ["echo", " purge "]}),
            serde_json::json!({}),
            serde_json::json!({"allowed_tools": "not-a-list"}),
            serde_json::json!({"allowed_tools": ["echo", ""], "mcp_tool_catalog": [{"name": "x"}]}),
        ]);
        assert_eq!(
            got,
            ["echo", "purge"].into_iter().map(str::to_string).collect()
        );
    }

    #[test]
    fn refusal_names_every_unapproved_tool() {
        let err = RuleToolsError::NotApproved(
            ["create_task", "purge"]
                .into_iter()
                .map(str::to_string)
                .collect(),
        );
        assert_eq!(
            err.to_string(),
            "tool(s) not approved on this asset group: create_task, purge"
        );
    }
}
