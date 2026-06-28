//! Canonical username normalization shared across services.
//!
//! Vauban treats login identifiers as **case-insensitive**: `Alice`,
//! `alice` and `ALICE` are the same account. To keep that contract
//! consistent between the storage layer (the DB enforces uniqueness on
//! `lower(username)`) and every code path that writes or looks up a
//! username, all of them funnel through [`normalize_username`].
//!
//! The normalization is intentionally minimal and deterministic:
//!
//! * leading / trailing ASCII (and Unicode) whitespace is trimmed -- a
//!   stray space pasted into a login form must never fork an identity;
//! * the remainder is lower-cased.
//!
//! Local usernames are constrained to ASCII by the creation regex
//! (`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`), so Rust's full-Unicode
//! `to_lowercase` agrees byte-for-byte with Postgres' `lower()` in
//! practice; directory-backed (LDAP/AD) identifiers are ASCII as well.
//! Keeping a single helper guarantees the app-level dedup checks and the
//! DB-level unique index can never drift apart.

/// Canonical, comparison-ready form of a login identifier: trimmed and
/// lower-cased. This is the value Vauban persists and the value every
/// `username = ?` lookup must compare against.
///
/// The original casing typed by a federated user is preserved elsewhere
/// (e.g. the `external_id` column) for audit / forensics; only the
/// `username` identity column is canonicalised.
#[must_use]
pub fn normalize_username(input: &str) -> String {
    input.trim().to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lowercases_ascii() {
        assert_eq!(normalize_username("Alice"), "alice");
        assert_eq!(normalize_username("ALICE"), "alice");
        assert_eq!(normalize_username("aLiCe"), "alice");
    }

    #[test]
    fn already_canonical_is_unchanged() {
        assert_eq!(normalize_username("alice"), "alice");
        assert_eq!(normalize_username("jean-dupont"), "jean-dupont");
        assert_eq!(normalize_username("user.name_1"), "user.name_1");
    }

    #[test]
    fn preserves_hyphens_dots_underscores() {
        assert_eq!(normalize_username("Jean-Dupont"), "jean-dupont");
        assert_eq!(normalize_username("User.Name"), "user.name");
        assert_eq!(normalize_username("Foo_Bar"), "foo_bar");
    }

    #[test]
    fn trims_surrounding_whitespace() {
        assert_eq!(normalize_username("  Alice  "), "alice");
        assert_eq!(normalize_username("\tBob\n"), "bob");
    }

    #[test]
    fn is_idempotent() {
        let once = normalize_username("  MixedCase-User  ");
        let twice = normalize_username(&once);
        assert_eq!(once, twice);
        assert_eq!(once, "mixedcase-user");
    }

    #[test]
    fn distinct_case_variants_collapse_to_same_value() {
        let variants = ["Admin", "admin", "ADMIN", "aDmIn", " admin "];
        for v in variants {
            assert_eq!(normalize_username(v), "admin", "variant {v:?}");
        }
    }
}
