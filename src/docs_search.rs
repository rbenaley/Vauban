//! Pure helpers shared by the docs list page and live search shard.

/// Trim and reject blank org slugs (shard args are attacker-controlled).
pub fn normalize_org_slug(raw: &str) -> Option<&str> {
    let slug = raw.trim();
    if slug.is_empty() { None } else { Some(slug) }
}

/// Trim + lowercase search query (page query params and shard `q` arg).
pub fn normalize_query(q: &str) -> String {
    q.trim().to_lowercase()
}

/// Trim category filter (exact match against stored category labels).
pub fn normalize_category(cat: &str) -> String {
    cat.trim().to_owned()
}

/// Case-insensitive title/summary match against an already-normalized query.
pub fn text_matches_query(q: &str, title: &str, summary: &str) -> bool {
    q.is_empty() || title.to_lowercase().contains(q) || summary.to_lowercase().contains(q)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn docs_search_shard_normalize_org_slug_rejects_blank() {
        assert_eq!(normalize_org_slug(""), None);
        assert_eq!(normalize_org_slug("   "), None);
        assert_eq!(normalize_org_slug("\t\n"), None);
        assert_eq!(normalize_org_slug(" acme "), Some("acme"));
        assert_eq!(normalize_org_slug("vauban"), Some("vauban"));
    }

    #[test]
    fn docs_search_shard_normalize_query_trims_and_lowercases() {
        assert_eq!(normalize_query("  SSH Tunnel  "), "ssh tunnel");
        assert_eq!(normalize_query(""), "");
        assert_eq!(normalize_query("   "), "");
    }

    #[test]
    fn docs_search_shard_text_matches_title_and_summary() {
        let q = normalize_query("Api");
        assert!(text_matches_query(&q, "REST API guide", "other"));
        assert!(text_matches_query(&q, "Guide", "Uses the API gateway"));
        assert!(!text_matches_query(&q, "Deployment", "ops only"));
        assert!(text_matches_query("", "anything", "goes"));
    }

    #[test]
    fn docs_search_shard_normalize_category_trims_only() {
        assert_eq!(normalize_category("  API  "), "API");
        assert_eq!(normalize_category("   "), "");
    }

    proptest! {
        #![proptest_config(crate::proptest_util::cases(48))]

        #[test]
        fn docs_search_shard_prop_query_normalization_idempotent(
            raw in " *[A-Za-z0-9 ._/-]{0,48} *"
        ) {
            let once = normalize_query(&raw);
            let twice = normalize_query(&once);
            prop_assert_eq!(&once, &twice);
            prop_assert!(!once.chars().any(|c| c.is_ascii_uppercase()));
            prop_assert_eq!(once.as_str(), once.trim());
        }

        #[test]
        fn docs_search_shard_prop_org_slug_whitespace_only_rejected(
            spaces in " *|\t*"
        ) {
            prop_assert_eq!(normalize_org_slug(&spaces), None);
        }

        #[test]
        fn docs_search_shard_prop_org_slug_preserves_trimmed(
            prefix in " *",
            body in "[A-Za-z0-9-]{1,24}",
            suffix in " *"
        ) {
            let raw = format!("{prefix}{body}{suffix}");
            prop_assert_eq!(normalize_org_slug(&raw), Some(body.as_str()));
        }

        #[test]
        fn docs_search_shard_prop_match_is_case_insensitive(
            needle in "[A-Za-z]{2,8}",
            pad in "[A-Za-z0-9 ]{0,12}"
        ) {
            let q = normalize_query(&needle);
            let title = format!("{pad}{}{pad}", needle.to_uppercase());
            prop_assert!(text_matches_query(&q, &title, "x"));
            prop_assert!(text_matches_query(&q, "x", &title));
        }
    }
}
