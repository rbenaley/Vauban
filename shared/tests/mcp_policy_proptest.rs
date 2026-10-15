use std::collections::BTreeSet;

use proptest::prelude::*;
use shared::mcp_drift_iam::{
    McpDriftIam, max_severity, normalize_mcp_drift_iam, parse_mcp_drift_iam,
};
use shared::mcp_policy::{
    McpRuleToolColumns, effective_callable_tools, flatten_pg_text_array, intersect_allow_sets,
    mcp_method_allowed, prune_rule_tools, rule_tools_outside, union_hitl_sets,
};

fn tool_name() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9_]{0,12}".prop_map(|s| s)
}

proptest! {
    #[test]
    fn allow_intersection_is_subset_of_every_rule(sets in prop::collection::vec(prop::collection::btree_set(tool_name(), 0..6), 1..5)) {
        let effective = intersect_allow_sets(sets.iter());
        for set in &sets {
            prop_assert!(effective.is_subset(set));
        }
    }

    #[test]
    fn hitl_union_contains_every_rule(sets in prop::collection::vec(prop::collection::btree_set(tool_name(), 0..6), 0..5)) {
        let union = union_hitl_sets(sets.iter());
        for set in &sets {
            prop_assert!(set.is_subset(&union));
        }
    }

    #[test]
    fn unknown_jsonrpc_methods_are_rejected(method in "[a-zA-Z0-9_./]{1,40}") {
        let known = [
            "initialize",
            "notifications/initialized",
            "tools/list",
            "tools/call",
        ];
        if known.contains(&method.as_str()) {
            prop_assert!(mcp_method_allowed(&method));
        } else {
            prop_assert!(!mcp_method_allowed(&method));
        }
    }
}

#[test]
fn empty_allow_intersection_is_deny_all() {
    let empty: Vec<BTreeSet<String>> = Vec::new();
    assert!(intersect_allow_sets(empty.iter()).is_empty());
}

fn column() -> impl Strategy<Value = Option<Vec<Option<String>>>> {
    prop::option::of(prop::collection::vec(
        prop::option::of(prop_oneof![
            "[a-d]",
            Just(" b ".to_string()),
            Just(String::new())
        ]),
        0..4,
    ))
}

fn rule() -> impl Strategy<Value = McpRuleToolColumns> {
    (column(), column(), column())
}

fn catalog() -> impl Strategy<Value = BTreeSet<String>> {
    prop::collection::btree_set("[a-e]", 0..5)
}

fn drift_iam() -> impl Strategy<Value = McpDriftIam> {
    prop::sample::select(McpDriftIam::ALL.to_vec())
}

proptest! {
    #[test]
    fn effective_tools_ignore_rule_order(rows in prop::collection::vec(rule(), 0..5), cat in prop::option::of(catalog()), seed in any::<u64>()) {
        let mut shuffled = rows.clone();
        let n = shuffled.len();
        if n > 1 {
            shuffled.rotate_left((seed as usize) % n);
            shuffled.swap(0, n - 1);
        }
        prop_assert_eq!(
            effective_callable_tools(rows, cat.clone()),
            effective_callable_tools(shuffled, cat)
        );
    }

    #[test]
    fn effective_tools_stay_inside_the_catalogue(rows in prop::collection::vec(rule(), 0..5), cat in catalog()) {
        prop_assert!(effective_callable_tools(rows, Some(cat.clone())).is_subset(&cat));
    }

    #[test]
    fn adding_a_rule_never_grants_more(rows in prop::collection::vec(rule(), 1..5), extra in rule(), cat in prop::option::of(catalog())) {
        let before = effective_callable_tools(rows.clone(), cat.clone());
        let mut more = rows;
        more.push(extra);
        prop_assert!(effective_callable_tools(more, cat).is_subset(&before));
    }

    #[test]
    fn a_tool_needs_every_rule_and_the_catalogue(rows in prop::collection::vec(rule(), 0..5), cat in prop::option::of(catalog())) {
        let out = effective_callable_tools(rows.clone(), cat.clone());
        for t in &out {
            prop_assert!(cat.as_ref().is_some_and(|c| c.contains(t)), "{} not approved", t);
            for (a, h, p) in &rows {
                let named = [a, h, p].iter().any(|c| {
                    c.iter().flatten().flatten().any(|n| n.trim() == t)
                });
                prop_assert!(named, "{} granted by a rule that does not name it", t);
            }
        }
    }

    #[test]
    fn a_rule_naming_nothing_denies_everything(rows in prop::collection::vec(rule(), 0..4), cat in prop::option::of(catalog())) {
        let mut with_null = rows;
        with_null.push((None, None, None));
        prop_assert!(effective_callable_tools(with_null, cat).is_empty());
    }

    #[test]
    fn no_catalogue_is_deny_all(rows in prop::collection::vec(rule(), 0..5)) {
        prop_assert!(effective_callable_tools(rows, None).is_empty());
    }

    #[test]
    fn zero_rules_is_deny_all(cat in prop::option::of(catalog())) {
        prop_assert!(effective_callable_tools(Vec::new(), cat).is_empty());
    }

    #[test]
    fn effective_tools_never_contain_blank_names(rows in prop::collection::vec(rule(), 0..5)) {
        let all: BTreeSet<String> = ["a", "b", "c", "d"].iter().map(|s| s.to_string()).collect();
        for t in effective_callable_tools(rows, Some(all)) {
            prop_assert!(!t.is_empty() && t.trim() == t);
        }
    }

    #[test]
    fn drift_max_severity_is_an_upper_bound(values in prop::collection::vec(drift_iam(), 1..6)) {
        let m = max_severity(values.clone());
        prop_assert!(values.contains(&m));
        for v in &values {
            prop_assert!(*v <= m);
        }
        let mut rev = values.clone();
        rev.reverse();
        prop_assert_eq!(max_severity(rev), m);
        prop_assert_eq!(max_severity([m, m]), m);
    }

    #[test]
    fn drift_iam_normalize_only_writes_known_tokens(raw in "\\PC{0,24}") {
        let n = normalize_mcp_drift_iam(&raw);
        prop_assert!(McpDriftIam::ALL.iter().any(|v| v.as_str() == n));
        if let Ok(v) = parse_mcp_drift_iam(&raw) {
            prop_assert_eq!(n, v.as_str());
        }
    }
}

fn named(cols: &McpRuleToolColumns) -> BTreeSet<String> {
    let (a, h, p) = cols.clone();
    let mut all = flatten_pg_text_array(a);
    all.extend(flatten_pg_text_array(h));
    all.extend(flatten_pg_text_array(p));
    all
}

proptest! {
    #[test]
    fn pruned_rule_names_only_approved_tools(cols in rule(), approved in catalog()) {
        let pruned = prune_rule_tools(cols.clone(), &approved);
        prop_assert!(named(&pruned).is_subset(&approved));
        prop_assert!(rule_tools_outside(&pruned, &approved).is_empty());
    }

    #[test]
    fn prune_never_adds_a_name_and_is_idempotent(cols in rule(), approved in catalog()) {
        let pruned = prune_rule_tools(cols.clone(), &approved);
        prop_assert!(named(&pruned).is_subset(&named(&cols)));
        prop_assert_eq!(prune_rule_tools(pruned.clone(), &approved), pruned);
    }

    #[test]
    fn prune_keeps_null_allow_null(cols in rule(), approved in catalog()) {
        let pruned = prune_rule_tools(cols.clone(), &approved);
        prop_assert_eq!(cols.0.is_none(), pruned.0.is_none());
        prop_assert!(pruned.1.as_ref().is_none_or(|v| !v.is_empty()));
        prop_assert!(pruned.2.as_ref().is_none_or(|v| !v.is_empty()));
    }

    #[test]
    fn outside_is_exactly_what_prune_removes(cols in rule(), approved in catalog()) {
        let outside = rule_tools_outside(&cols, &approved);
        let removed: BTreeSet<String> = named(&cols)
            .difference(&named(&prune_rule_tools(cols.clone(), &approved)))
            .cloned()
            .collect();
        prop_assert_eq!(&outside, &removed);
        prop_assert!(outside.is_disjoint(&approved));
    }

    /// The approved set of a group covers the catalogue of each of its
    /// assets, so pruning never changes what a session can call.
    #[test]
    fn prune_never_changes_effective_tools(
        rows in prop::collection::vec(rule(), 0..5),
        cat in catalog(),
        extra in catalog(),
    ) {
        let approved: BTreeSet<String> = cat.union(&extra).cloned().collect();
        let pruned: Vec<McpRuleToolColumns> = rows
            .iter()
            .cloned()
            .map(|r| prune_rule_tools(r, &approved))
            .collect();
        prop_assert_eq!(
            effective_callable_tools(rows, Some(cat.clone())),
            effective_callable_tools(pruned, Some(cat))
        );
    }
}

#[test]
fn drift_max_severity_of_nothing_is_the_default() {
    assert_eq!(max_severity(Vec::new()), McpDriftIam::SuspendGroup);
}
