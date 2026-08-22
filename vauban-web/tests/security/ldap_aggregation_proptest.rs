//! Property tests for LDAPS aggregation A/B/C transitions.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use proptest::prelude::*;
use vauban_web::services::ldap_aggregation::{AggregationAction, AggregationCase, decide_action};

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
}
