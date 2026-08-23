//! Property tests for LDAPS aggregation A/B/C transitions.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;

use proptest::prelude::*;
use vauban_web::services::ldap_aggregation::{
    AggregationAction, AggregationCase, build_aggregation_delta, decide_action,
};

fn case_strategy() -> impl Strategy<Value = AggregationCase> {
    prop_oneof![
        Just(AggregationCase::Complete),
        Just(AggregationCase::IncompleteNotFound),
        Just(AggregationCase::IncompleteUnreachable),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn complete_always_replace_set(streak in 0u32..=10_000, threshold in 0u32..=100) {
        prop_assert_eq!(
            decide_action(AggregationCase::Complete, streak, threshold),
            AggregationAction::ReplaceSet
        );
    }

    #[test]
    fn threshold_zero_incomplete_always_holds(case in case_strategy(), streak in 0u32..=10_000) {
        prop_assume!(case != AggregationCase::Complete);
        prop_assert_eq!(
            decide_action(case, streak, 0),
            AggregationAction::Hold
        );
    }

    #[test]
    fn incomplete_purges_exactly_at_or_above_threshold(
        case in case_strategy(),
        streak in 1u32..=200,
        threshold in 1u32..=200,
    ) {
        prop_assume!(case != AggregationCase::Complete);
        let action = decide_action(case, streak, threshold);
        if streak >= threshold {
            prop_assert_eq!(action, AggregationAction::PurgeFailsafe);
        } else {
            prop_assert_eq!(action, AggregationAction::Hold);
        }
    }

    #[test]
    fn delta_added_removed_are_set_difference(
        desired in prop::collection::btree_set("[a-z]{1,6}", 0..12),
        previous in prop::collection::btree_set("[a-z]{1,6}", 0..12),
    ) {
        let catalogue: Vec<(i32, String)> = desired
            .union(&previous)
            .enumerate()
            .map(|(i, n)| (i as i32 + 1, n.clone()))
            .collect();
        let current: Vec<(i32, String)> = catalogue
            .iter()
            .filter(|(_, n)| previous.contains(n))
            .cloned()
            .collect();
        let delta = build_aggregation_delta(&desired, &catalogue, &current, None);
        let added: BTreeSet<String> = delta.payload.added.iter().cloned().collect();
        let removed: BTreeSet<String> = delta.payload.removed.iter().cloned().collect();
        prop_assert!(added.is_disjoint(&removed));
        prop_assert_eq!(
            &added,
            &desired.difference(&previous).cloned().collect::<BTreeSet<_>>()
        );
        prop_assert_eq!(
            &removed,
            &previous.difference(&desired).cloned().collect::<BTreeSet<_>>()
        );
        prop_assert_eq!(delta.payload.desired, desired.len());
        prop_assert_eq!(delta.payload.previous, previous.len());
        prop_assert!(delta.payload.unmapped.is_empty());
    }
}
