//! Pure helpers shared by org/admin issues pages and live search shards.

/// Trim + lowercase search query (key / title).
pub fn normalize_query(q: &str) -> String {
    q.trim().to_lowercase()
}

/// Trim status chip filter (compared case-insensitively).
pub fn normalize_status(status: &str) -> String {
    status.trim().to_owned()
}

/// Trim org slug/id filter for admin issues.
pub fn normalize_org_filter(raw: &str) -> String {
    raw.trim().to_owned()
}

/// Case-insensitive key/title match against an already-normalized query.
pub fn issue_matches_query(q: &str, key: &str, title: &str) -> bool {
    q.is_empty() || key.to_lowercase().contains(q) || title.to_lowercase().contains(q)
}

/// Status chip match (`""` means all).
pub fn issue_matches_status(status: &str, issue_status: &str) -> bool {
    status.is_empty() || issue_status.eq_ignore_ascii_case(status)
}

/// Resolve admin org filter (numeric id or slug) against known orgs.
pub fn resolve_org_filter<'a, I>(orgs: I, raw: &str) -> Option<u64>
where
    I: IntoIterator<Item = (u64, &'a str)>,
{
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let mut by_slug: Option<u64> = None;
    let mut id_hit: Option<u64> = None;
    let parsed = raw.parse::<u64>().ok();
    for (id, slug) in orgs {
        if parsed == Some(id) {
            id_hit = Some(id);
        }
        if slug.eq_ignore_ascii_case(raw) {
            by_slug = Some(id);
        }
    }
    id_hit.or(by_slug)
}

/// Whether an issue belongs under a resolved org filter.
pub fn issue_matches_org(
    org_filter: &str,
    org_id_filter: Option<u64>,
    organization_id: u64,
) -> bool {
    if org_filter.is_empty() {
        true
    } else {
        org_id_filter == Some(organization_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn issues_search_shard_normalize_query_trims_and_lowercases() {
        assert_eq!(normalize_query("  VBN-1  "), "vbn-1");
        assert_eq!(normalize_query("   "), "");
    }

    #[test]
    fn issues_search_shard_issue_matches_query_key_and_title() {
        let q = normalize_query("Vbn");
        assert!(issue_matches_query(&q, "VBN-201", "other"));
        assert!(issue_matches_query(&q, "X", "VBN gateway"));
        assert!(!issue_matches_query(&q, "ISS-1", "billing"));
        assert!(issue_matches_query("", "any", "thing"));
    }

    #[test]
    fn issues_search_shard_issue_matches_status() {
        assert!(issue_matches_status("", "Open"));
        assert!(issue_matches_status("Open", "open"));
        assert!(!issue_matches_status("Closed", "Open"));
    }

    #[test]
    fn issues_search_shard_resolve_org_filter_by_id_and_slug() {
        let orgs = [(1u64, "acme"), (2u64, "beta")];
        assert_eq!(resolve_org_filter(orgs, ""), None);
        assert_eq!(resolve_org_filter(orgs, "   "), None);
        assert_eq!(resolve_org_filter(orgs, "1"), Some(1));
        assert_eq!(resolve_org_filter(orgs, "Acme"), Some(1));
        assert_eq!(resolve_org_filter(orgs, "missing"), None);
        assert_eq!(resolve_org_filter(orgs, "99"), None);
    }

    #[test]
    fn issues_search_shard_issue_matches_org_empty_or_resolved() {
        assert!(issue_matches_org("", None, 1));
        assert!(issue_matches_org("acme", Some(1), 1));
        assert!(!issue_matches_org("acme", Some(1), 2));
        assert!(!issue_matches_org("missing", None, 1));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]

        #[test]
        fn issues_search_shard_prop_query_normalization_idempotent(
            raw in " *[A-Za-z0-9 -]{0,40} *"
        ) {
            let once = normalize_query(&raw);
            let twice = normalize_query(&once);
            prop_assert_eq!(&once, &twice);
            prop_assert!(!once.chars().any(|c| c.is_ascii_uppercase()));
            prop_assert_eq!(once.as_str(), once.trim());
        }

        #[test]
        fn issues_search_shard_prop_status_trim_preserves_inner(
            pad_l in " *",
            body in "[A-Za-z ]{0,20}",
            pad_r in " *"
        ) {
            let raw = format!("{pad_l}{body}{pad_r}");
            prop_assert_eq!(normalize_status(&raw), body.trim());
        }

        #[test]
        fn issues_search_shard_prop_match_case_insensitive(needle in "[A-Za-z]{3,10}") {
            let q = normalize_query(&needle);
            let key = needle.to_uppercase();
            prop_assert!(issue_matches_query(&q, &key, "zzz"));
            prop_assert!(issue_matches_query(&q, "zzz", &key));
        }

        #[test]
        fn issues_search_shard_prop_resolve_prefers_existing_id(
            id in 1u64..10_000,
            slug in "[a-z][a-z0-9-]{1,12}"
        ) {
            let orgs = [(id, slug.as_str())];
            prop_assert_eq!(resolve_org_filter(orgs, &id.to_string()), Some(id));
            prop_assert_eq!(resolve_org_filter(orgs, &slug), Some(id));
            prop_assert_eq!(resolve_org_filter(orgs, &slug.to_uppercase()), Some(id));
        }
    }
}
