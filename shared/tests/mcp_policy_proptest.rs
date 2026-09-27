use std::collections::BTreeSet;

use proptest::prelude::*;
use shared::mcp_policy::{intersect_allow_sets, mcp_method_allowed, union_hitl_sets};

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
