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
/// `None` = this rule does not shrink the whitelist (NULL allow, no gates).
/// `Some([])` = deny-all (empty allow-list and no gates).
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
}
