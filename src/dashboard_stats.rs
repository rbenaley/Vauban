//! Pure helpers for org dashboard issue/doc summary stats.
//!
//! Typical orgs have tens of issues — one org-scoped load + in-process
//! aggregation is cheaper than multiple SQL `COUNT(*)` round-trips.

use crate::{
    issue_status::issue_is_closed,
    models::{ISSUE_STATUS_IN_ANALYSIS, Issue},
};

/// Safety cap for the single org issues fetch (product expectation: tens).
pub const DASHBOARD_ISSUES_CAP: usize = 500;

/// Aggregates derived from one org-scoped issue list (newest-first).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DashboardIssueStats {
    pub open_count: usize,
    pub in_analysis_count: usize,
}

/// Summarize issue tiles from rows already ordered by `updated_at` DESC
/// (or any order — counts do not depend on order; caller picks `latest` separately).
pub fn summarize_issue_stats(issues: &[Issue]) -> DashboardIssueStats {
    let mut open_count = 0usize;
    let mut in_analysis_count = 0usize;
    for issue in issues {
        if !issue_is_closed(&issue.status) {
            open_count += 1;
        }
        if issue.status.eq_ignore_ascii_case(ISSUE_STATUS_IN_ANALYSIS) {
            in_analysis_count += 1;
        }
    }
    DashboardIssueStats {
        open_count,
        in_analysis_count,
    }
}

/// Newest issue by `updated_at` (stable tie-break on `id`).
pub fn latest_issue_by_updated_at(issues: &[Issue]) -> Option<&Issue> {
    issues.iter().max_by(|a, b| {
        a.updated_at
            .cmp(&b.updated_at)
            .then_with(|| a.id.cmp(&b.id))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ISSUE_STATUS_CLOSED, ISSUE_STATUS_OPEN, ISSUE_STATUS_RESOLVED, Issue};
    use proptest::prelude::*;

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

    #[test]
    fn summarize_counts_open_and_in_analysis() {
        let rows = vec![
            sample(1, ISSUE_STATUS_OPEN, 10),
            sample(2, ISSUE_STATUS_IN_ANALYSIS, 20),
            sample(3, ISSUE_STATUS_RESOLVED, 30),
            sample(4, ISSUE_STATUS_CLOSED, 40),
            sample(5, "in analysis", 50),
        ];
        let stats = summarize_issue_stats(&rows);
        assert_eq!(stats.open_count, 3); // open + 2× in analysis
        assert_eq!(stats.in_analysis_count, 2);
    }

    #[test]
    fn latest_picks_highest_updated_at() {
        let rows = vec![
            sample(1, ISSUE_STATUS_OPEN, 10),
            sample(2, ISSUE_STATUS_OPEN, 40),
            sample(3, ISSUE_STATUS_OPEN, 20),
        ];
        let latest = latest_issue_by_updated_at(&rows).expect("latest");
        assert_eq!(latest.id, 2);
    }

    #[test]
    fn empty_stats_are_zero() {
        let stats = summarize_issue_stats(&[]);
        assert_eq!(stats.open_count, 0);
        assert_eq!(stats.in_analysis_count, 0);
        assert!(latest_issue_by_updated_at(&[]).is_none());
    }

    proptest! {
        #![proptest_config(crate::proptest_util::cases(48))]

        #[test]
        fn prop_open_plus_closed_equals_len(
            statuses in prop::collection::vec(
                prop_oneof![
                    Just(ISSUE_STATUS_OPEN.to_owned()),
                    Just(ISSUE_STATUS_IN_ANALYSIS.to_owned()),
                    Just(ISSUE_STATUS_RESOLVED.to_owned()),
                    Just(ISSUE_STATUS_CLOSED.to_owned()),
                ],
                0..40
            )
        ) {
            let rows: Vec<Issue> = statuses
                .iter()
                .enumerate()
                .map(|(i, s)| sample(i as u64 + 1, s, i as i64))
                .collect();
            let stats = summarize_issue_stats(&rows);
            let closed = rows.iter().filter(|i| issue_is_closed(&i.status)).count();
            prop_assert_eq!(stats.open_count + closed, rows.len());
            prop_assert!(stats.in_analysis_count <= stats.open_count);
        }
    }
}
