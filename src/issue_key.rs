//! Org-scoped public issue key allocation (`VBN-{n}`).

use toasty::Db;

use crate::models::Issue;

/// Product convention: first issue in an empty org is `VBN-200`.
pub const ISSUE_KEY_START: u32 = 200;

/// Prefix for allocated public keys.
pub const ISSUE_KEY_PREFIX: &str = "VBN-";

/// Max create attempts when a unique `(organization_id, key)` races.
pub const ISSUE_KEY_CREATE_ATTEMPTS: u32 = 12;

/// Parse the numeric suffix of a `VBN-{n}` key. Non-matching keys are ignored.
pub fn parse_vbn_suffix(key: &str) -> Option<u32> {
    let rest = key.strip_prefix(ISSUE_KEY_PREFIX)?;
    if rest.is_empty() || !rest.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    rest.parse().ok()
}

/// Next public key from an org-scoped set of existing keys.
///
/// Empty / non-`VBN-*` sets yield `VBN-200`. Otherwise
/// `max(199, max_seen).saturating_add(1)`.
pub fn next_issue_key_from_keys<'a, I>(keys: I) -> String
where
    I: IntoIterator<Item = &'a str>,
{
    let mut max_seen: Option<u32> = None;
    for key in keys {
        if let Some(n) = parse_vbn_suffix(key) {
            max_seen = Some(max_seen.map_or(n, |m| m.max(n)));
        }
    }
    let next = match max_seen {
        None => ISSUE_KEY_START,
        Some(n) => n.max(ISSUE_KEY_START.saturating_sub(1)).saturating_add(1),
    };
    format!("{ISSUE_KEY_PREFIX}{next}")
}

/// Load org-scoped issue keys and allocate the next `VBN-{n}`.
pub async fn allocate_issue_key(db: &mut Db, organization_id: u64) -> String {
    let rows = Issue::all()
        .filter(Issue::fields().organization_id().eq(organization_id))
        .exec(db)
        .await
        .unwrap_or_default();
    next_issue_key_from_keys(rows.iter().map(|i| i.key.as_str()))
}

/// True when a Toasty/Postgres error looks like a unique constraint violation.
pub fn is_unique_violation(err: &impl std::fmt::Display) -> bool {
    let s = err.to_string().to_lowercase();
    s.contains("unique") || s.contains("duplicate key") || s.contains("23505")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_vbn_suffix_accepts_digits() {
        assert_eq!(parse_vbn_suffix("VBN-200"), Some(200));
        assert_eq!(parse_vbn_suffix("VBN-0"), Some(0));
        assert_eq!(parse_vbn_suffix("VBN-214"), Some(214));
    }

    #[test]
    fn parse_vbn_suffix_rejects_non_matching() {
        assert_eq!(parse_vbn_suffix("vbn-200"), None);
        assert_eq!(parse_vbn_suffix("VBN-"), None);
        assert_eq!(parse_vbn_suffix("VBN-20a"), None);
        assert_eq!(parse_vbn_suffix("TEST-200"), None);
        assert_eq!(parse_vbn_suffix(""), None);
    }

    #[test]
    fn next_key_empty_org_starts_at_200() {
        let empty: &[&str] = &[];
        assert_eq!(next_issue_key_from_keys(empty.iter().copied()), "VBN-200");
    }

    #[test]
    fn next_key_max_suffix_plus_one() {
        assert_eq!(
            next_issue_key_from_keys(["VBN-200", "VBN-214", "VBN-201"].into_iter()),
            "VBN-215"
        );
    }

    #[test]
    fn next_key_ignores_non_vbn() {
        assert_eq!(
            next_issue_key_from_keys(["TEST-999", "VBN-210", "other"].into_iter()),
            "VBN-211"
        );
    }

    #[test]
    fn next_key_preserves_floor_when_below_start() {
        // max_seen < 199 → still advance from floor so empty-org convention holds.
        assert_eq!(next_issue_key_from_keys(["VBN-50"].into_iter()), "VBN-200");
    }

    #[test]
    fn unique_violation_matches_common_driver_messages() {
        assert!(is_unique_violation(
            &"duplicate key value violates unique constraint \"index_issues_by_organization_id_and_key\""
        ));
        assert!(is_unique_violation(&"ERROR: unique_violation (23505)"));
        assert!(!is_unique_violation(&"connection reset by peer"));
    }
}
