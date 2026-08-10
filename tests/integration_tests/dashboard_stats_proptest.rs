//! Property tests for dashboard issue stats aggregation.

use proptest::prelude::*;
use vcp::{
    dashboard_stats::{latest_issue_by_updated_at, summarize_issue_stats},
    models::{
        ISSUE_STATUS_CLOSED, ISSUE_STATUS_IN_ANALYSIS, ISSUE_STATUS_OPEN, ISSUE_STATUS_RESOLVED,
        Issue,
    },
};

fn sample(id: u64, status: &str, updated_at: i64) -> Issue {
    Issue {
        id,
        key: format!("VBN-{id}"),
        title: "t".to_owned(),
        component: "c".to_owned(),
        severity: "Medium".to_owned(),
        status: status.to_owned(),
        organization_id: 1,
        details: String::new(),
        opened_by_user_id: 1,
        created_at: updated_at,
        updated_at,
        version: 1,
    }
}

proptest! {
    #![proptest_config(crate::common::prop_config(64))]

    #[test]
    fn prop_open_and_analysis_are_disjoint_fsm_counts(
        statuses in prop::collection::vec(
            prop_oneof![
                Just(ISSUE_STATUS_OPEN.to_owned()),
                Just(ISSUE_STATUS_IN_ANALYSIS.to_owned()),
                Just(ISSUE_STATUS_RESOLVED.to_owned()),
                Just(ISSUE_STATUS_CLOSED.to_owned()),
            ],
            0..60
        )
    ) {
        let rows: Vec<Issue> = statuses
            .iter()
            .enumerate()
            .map(|(i, s)| sample(i as u64 + 1, s, i as i64))
            .collect();
        let stats = summarize_issue_stats(&rows);
        let open = rows
            .iter()
            .filter(|i| i.status.eq_ignore_ascii_case(ISSUE_STATUS_OPEN))
            .count();
        let analysis = rows
            .iter()
            .filter(|i| i.status.eq_ignore_ascii_case(ISSUE_STATUS_IN_ANALYSIS))
            .count();
        let terminal = rows
            .iter()
            .filter(|i| {
                i.status.eq_ignore_ascii_case(ISSUE_STATUS_RESOLVED)
                    || i.status.eq_ignore_ascii_case(ISSUE_STATUS_CLOSED)
            })
            .count();
        prop_assert_eq!(stats.open_count, open);
        prop_assert_eq!(stats.in_analysis_count, analysis);
        prop_assert_eq!(
            stats.open_count + stats.in_analysis_count + terminal,
            rows.len()
        );
    }

    #[test]
    fn prop_latest_matches_max_updated_at(
        stamps in prop::collection::vec(0i64..10_000, 1..40)
    ) {
        let rows: Vec<Issue> = stamps
            .iter()
            .enumerate()
            .map(|(i, &t)| sample(i as u64 + 1, ISSUE_STATUS_OPEN, t))
            .collect();
        let latest = latest_issue_by_updated_at(&rows).expect("non-empty");
        let max_t = stamps.iter().copied().max().expect("max");
        prop_assert_eq!(latest.updated_at, max_t);
        let tied: Vec<_> = rows.iter().filter(|i| i.updated_at == max_t).collect();
        let expected_id = tied.iter().map(|i| i.id).max().expect("tie id");
        prop_assert_eq!(latest.id, expected_id);
    }

    #[test]
    fn prop_cap_constant_covers_typical_org(n in 0usize..80) {
        // Product expectation: tens of issues/org; cap must stay above that.
        prop_assert!(n < vcp::dashboard_stats::DASHBOARD_ISSUES_CAP);
        prop_assert!(vcp::dashboard_stats::DASHBOARD_ISSUES_CAP >= 100);
    }
}
