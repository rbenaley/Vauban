//! MCP access-rule callable set. One copy for hop-1 mint (`vauban-access`)
//! and web session preview (`vauban-web`).

use std::collections::BTreeSet;

pub fn flatten_pg_text_array(raw: Option<Vec<Option<String>>>) -> BTreeSet<String> {
    raw.into_iter()
        .flatten()
        .flatten()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// JSON-RPC methods the PEP may relay. Anything else is refused before upstream.
pub fn mcp_method_allowed(method: &str) -> bool {
    matches!(
        method,
        "initialize" | "notifications/initialized" | "tools/list" | "tools/call"
    )
}

/// Intersection of per-rule Allow sets. An empty input is deny-all.
pub fn intersect_allow_sets<'a>(
    sets: impl IntoIterator<Item = &'a BTreeSet<String>>,
) -> BTreeSet<String> {
    let mut iter = sets.into_iter();
    let Some(first) = iter.next() else {
        return BTreeSet::new();
    };
    let mut acc = first.clone();
    for set in iter {
        acc = acc.intersection(set).cloned().collect();
    }
    acc
}

/// Union of per-rule HITL force-lists.
pub fn union_hitl_sets<'a>(
    sets: impl IntoIterator<Item = &'a BTreeSet<String>>,
) -> BTreeSet<String> {
    sets.into_iter().fold(BTreeSet::new(), |mut acc, set| {
        acc.extend(set.iter().cloned());
        acc
    })
}

/// Callable set for one rule: `allow ∪ HITL ∪ require_plan`.
/// `None` = the rule names no tool (NULL allow, no gates): it grants nothing.
/// `Some([])` = empty allow-list and no gates: also grants nothing.
pub fn mcp_rule_callable_tools(
    allow: Option<Vec<Option<String>>>,
    hitl: Option<Vec<Option<String>>>,
    plan: Option<Vec<Option<String>>>,
) -> Option<BTreeSet<String>> {
    let mut gates = flatten_pg_text_array(hitl);
    gates.extend(flatten_pg_text_array(plan));
    match allow {
        None if gates.is_empty() => None,
        None => Some(gates),
        Some(list) => {
            let mut set = flatten_pg_text_array(Some(list));
            set.extend(gates);
            Some(set)
        }
    }
}

/// One applicable access rule: `(mcp_allowed_tools, mcp_hitl_tools,
/// mcp_require_plan_tools)` as loaded from Postgres.
pub type McpRuleToolColumns = (
    Option<Vec<Option<String>>>,
    Option<Vec<Option<String>>>,
    Option<Vec<Option<String>>>,
);

/// Effective callable set for one (user, asset): a tool is callable only if
/// every applicable rule names it AND the asset catalogue approves it.
///
/// A rule that names no tool (NULL columns) grants nothing, so it empties the
/// intersection. Zero rules, or no approved catalogue, is deny-all.
pub fn effective_callable_tools(
    rows: impl IntoIterator<Item = McpRuleToolColumns>,
    catalog: Option<BTreeSet<String>>,
) -> BTreeSet<String> {
    let Some(catalog) = catalog else {
        return BTreeSet::new();
    };
    let mut effective: Option<BTreeSet<String>> = None;
    for (allow, hitl, plan) in rows {
        let set = mcp_rule_callable_tools(allow, hitl, plan).unwrap_or_default();
        effective = Some(match effective {
            None => set,
            Some(prev) => prev.intersection(&set).cloned().collect(),
        });
    }
    effective
        .map(|rule_set| rule_set.intersection(&catalog).cloned().collect())
        .unwrap_or_default()
}

/// Prefix of the vauban-access refusal when a rule names a tool that is not
/// approved on its asset group. vauban-web shows the message as-is.
pub const RULE_TOOLS_NOT_APPROVED: &str = "tool(s) not approved on this asset group";

/// Tool names a rule names (any of its three columns) that `approved`
/// does not contain. Blank entries are not names and are ignored.
pub fn rule_tools_outside(
    cols: &McpRuleToolColumns,
    approved: &BTreeSet<String>,
) -> BTreeSet<String> {
    let (allow, hitl, plan) = cols;
    [allow, hitl, plan]
        .into_iter()
        .flat_map(|col| flatten_pg_text_array(col.clone()))
        .filter(|name| !approved.contains(name))
        .collect()
}

/// Rule columns with every name outside `approved` removed.
///
/// A NULL column stays NULL. The allow column keeps `Some([])` when every
/// name goes (it grants nothing either way). HITL and Require plan become
/// NULL when empty, as vauban-web writes them.
pub fn prune_rule_tools(
    cols: McpRuleToolColumns,
    approved: &BTreeSet<String>,
) -> McpRuleToolColumns {
    let keep = |col: Option<Vec<Option<String>>>| -> Option<Vec<Option<String>>> {
        col.map(|items| {
            let mut seen = BTreeSet::new();
            items
                .into_iter()
                .flatten()
                .map(|s| s.trim().to_string())
                .filter(|s| approved.contains(s) && seen.insert(s.clone()))
                .map(Some)
                .collect()
        })
    };
    let (allow, hitl, plan) = cols;
    let gate = |col| keep(col).filter(|v: &Vec<Option<String>>| !v.is_empty());
    (keep(allow), gate(hitl), gate(plan))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unions_hitl_and_require_plan() {
        assert_eq!(mcp_rule_callable_tools(None, None, None), None);
        assert_eq!(
            mcp_rule_callable_tools(Some(vec![]), None, None),
            Some(BTreeSet::new())
        );
        let set = mcp_rule_callable_tools(
            Some(vec![Some("echo".into())]),
            Some(vec![Some("hitl_demo".into())]),
            Some(vec![Some("read_demo_file".into())]),
        )
        .expect("legacy checkbox rule must stay callable");
        assert!(set.contains("echo"));
        assert!(set.contains("hitl_demo"));
        assert!(set.contains("read_demo_file"));
        let gates_only = mcp_rule_callable_tools(
            None,
            Some(vec![Some("hitl_demo".into()), Some("".into())]),
            Some(vec![Some("  ".into()), Some("read_demo_file".into())]),
        )
        .expect("NULL allow + gates must write a callable set");
        assert_eq!(
            gates_only,
            ["hitl_demo", "read_demo_file"]
                .into_iter()
                .map(str::to_string)
                .collect()
        );
        assert_eq!(
            flatten_pg_text_array(Some(vec![None, Some(" echo ".into())])),
            ["echo"].into_iter().map(str::to_string).collect()
        );
    }

    fn col(names: &[&str]) -> Option<Vec<Option<String>>> {
        Some(names.iter().map(|n| Some((*n).to_string())).collect())
    }

    fn set(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|n| (*n).to_string()).collect()
    }

    #[test]
    fn rule_tools_outside_lists_unapproved_names_from_every_column() {
        let approved = set(&["echo"]);
        assert!(rule_tools_outside(&(None, None, None), &approved).is_empty());
        assert!(rule_tools_outside(&(Some(vec![]), None, None), &approved).is_empty());
        assert!(
            rule_tools_outside(&(col(&[" echo ", "", "  "]), None, None), &approved).is_empty()
        );
        assert_eq!(
            rule_tools_outside(
                &(
                    col(&["echo", "create_task"]),
                    col(&["purge"]),
                    col(&["read_file"])
                ),
                &approved,
            ),
            set(&["create_task", "purge", "read_file"])
        );
        assert_eq!(
            rule_tools_outside(&(col(&["echo"]), None, None), &BTreeSet::new()),
            set(&["echo"])
        );
    }

    #[test]
    fn prune_rule_tools_keeps_null_and_only_approved_names() {
        let approved = set(&["echo", "purge"]);
        assert_eq!(
            prune_rule_tools((None, None, None), &approved),
            (None, None, None)
        );
        assert_eq!(
            prune_rule_tools((Some(vec![]), Some(vec![]), Some(vec![])), &approved),
            (Some(vec![]), None, None)
        );
        assert_eq!(
            prune_rule_tools(
                (
                    col(&["echo", "create_task", "echo", " purge "]),
                    col(&["purge", "create_task"]),
                    col(&["create_task"]),
                ),
                &approved,
            ),
            (col(&["echo", "purge"]), col(&["purge"]), None)
        );
        assert_eq!(
            prune_rule_tools((col(&["create_task"]), None, None), &approved),
            (Some(vec![]), None, None)
        );
        assert_eq!(
            prune_rule_tools((col(&["echo"]), col(&["purge"]), None), &BTreeSet::new()),
            (Some(vec![]), None, None)
        );
    }
}
