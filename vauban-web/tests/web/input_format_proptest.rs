//! Property-based invariants for the closed-format input validators
//! (`shared::validation`), the strict asset-status parser and the
//! web/API username-rule equivalence.
//!
//! These lock the format contracts introduced by the July 2026 input
//! validation hardening (group slugs / vault secret names accepted
//! arbitrary strings like "Prod uction {BUG}"):
//!
//! 1. **Totality** -- no validator panics on arbitrary Unicode input.
//! 2. **Slug grammar** -- exactly `^[a-z0-9]([a-z0-9_-]*[a-z0-9])?$`,
//!    1..=100 bytes; anything with uppercase, whitespace, exotic
//!    characters or edge separators is rejected.
//! 3. **Hex color** -- exactly `#` + 6 hex digits.
//! 4. **Status** -- `AssetStatus::parse_strict` accepts exactly the
//!    four canonical strings (no `Unknown` laundering on writes).
//! 5. **Web/API equivalence** -- the web-zone username helper accepts
//!    a string iff the API-zone `RE_USERNAME` + length bounds do:
//!    the two zones can never drift apart.

use proptest::prelude::*;
use shared::validation::{
    ICON_CATALOG, is_valid_hex_color, is_valid_hostname, is_valid_icon, is_valid_slug,
};
use vauban_web::models::asset::AssetStatus;
use vauban_web::models::user::RE_USERNAME;

/// Strategy producing strings from the canonical slug grammar.
fn valid_slug_strategy() -> impl Strategy<Value = String> {
    // edge chars alphanumeric, interior chars may add '-' and '_'.
    ("[a-z0-9]", "[a-z0-9_-]{0,80}", "[a-z0-9]").prop_map(|(head, mid, tail)| {
        if mid.is_empty() {
            // 2-char slug: head + tail (both alphanumeric).
            format!("{head}{tail}")
        } else {
            format!("{head}{mid}{tail}")
        }
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    // ------------------------------------------------------------------
    // 1. Totality: no panic on arbitrary Unicode, ever.
    // ------------------------------------------------------------------

    #[test]
    fn validators_are_total_on_arbitrary_unicode(s in "\\PC*") {
        let _ = is_valid_slug(&s);
        let _ = is_valid_hex_color(&s);
        let _ = is_valid_icon(&s);
        let _ = is_valid_hostname(&s);
        let _ = AssetStatus::parse_strict(&s);
        let _ = AssetStatus::parse(&s);
    }

    // ------------------------------------------------------------------
    // 2. Slug grammar.
    // ------------------------------------------------------------------

    #[test]
    fn every_grammar_generated_slug_is_accepted(slug in valid_slug_strategy()) {
        prop_assert!(is_valid_slug(&slug), "grammar-valid slug rejected: {slug:?}");
    }

    #[test]
    fn slug_acceptance_implies_grammar_membership(s in "\\PC{0,120}") {
        if is_valid_slug(&s) {
            prop_assert!(!s.is_empty() && s.len() <= 100);
            prop_assert!(
                s.bytes().all(|b| b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || b == b'-'
                    || b == b'_'),
                "accepted slug carries a char outside [a-z0-9_-]: {s:?}"
            );
            let first = s.as_bytes()[0];
            let last = s.as_bytes()[s.len() - 1];
            prop_assert!(first.is_ascii_lowercase() || first.is_ascii_digit());
            prop_assert!(last.is_ascii_lowercase() || last.is_ascii_digit());
        }
    }

    #[test]
    fn slug_with_uppercase_is_rejected(
        prefix in "[a-z0-9]{0,10}",
        upper in "[A-Z]{1,5}",
        suffix in "[a-z0-9]{0,10}",
    ) {
        let s = format!("{prefix}{upper}{suffix}");
        prop_assert!(!is_valid_slug(&s), "uppercase slug accepted: {s:?}");
    }

    #[test]
    fn slug_with_whitespace_is_rejected(
        prefix in "[a-z0-9]{1,10}",
        ws in "[ \\t\\n\\r]{1,3}",
        suffix in "[a-z0-9]{1,10}",
    ) {
        let s = format!("{prefix}{ws}{suffix}");
        prop_assert!(!is_valid_slug(&s), "whitespace slug accepted: {s:?}");
    }

    #[test]
    fn slug_with_edge_separator_is_rejected(
        core in "[a-z0-9]{1,10}",
        sep in prop_oneof![Just('-'), Just('_')],
        leading in any::<bool>(),
    ) {
        let s = if leading {
            format!("{sep}{core}")
        } else {
            format!("{core}{sep}")
        };
        prop_assert!(!is_valid_slug(&s), "edge-separator slug accepted: {s:?}");
    }

    #[test]
    fn slug_over_100_bytes_is_rejected(extra in 1usize..40) {
        let s = "a".repeat(100 + extra);
        prop_assert!(!is_valid_slug(&s));
    }

    #[test]
    fn slug_validation_is_deterministic(s in "\\PC{0,120}") {
        prop_assert_eq!(is_valid_slug(&s), is_valid_slug(&s));
    }

    // ------------------------------------------------------------------
    // 3. Hex color.
    // ------------------------------------------------------------------

    #[test]
    fn hash_plus_six_hex_digits_is_accepted(hex in "[0-9a-fA-F]{6}") {
        let color = format!("#{}", hex);
        prop_assert!(is_valid_hex_color(&color));
    }

    #[test]
    fn color_acceptance_implies_hash_plus_six_hex(s in "\\PC{0,20}") {
        if is_valid_hex_color(&s) {
            prop_assert_eq!(s.len(), 7);
            prop_assert!(s.starts_with('#'));
            prop_assert!(s.as_bytes()[1..].iter().all(u8::is_ascii_hexdigit));
        }
    }

    #[test]
    fn wrong_length_hex_is_rejected(hex in "[0-9a-f]{1,12}") {
        prop_assume!(hex.len() != 6);
        let color = format!("#{}", hex);
        prop_assert!(!is_valid_hex_color(&color));
    }

    #[test]
    fn six_hex_without_hash_is_rejected(hex in "[0-9a-fA-F]{6}") {
        prop_assert!(!is_valid_hex_color(&hex));
    }

    // ------------------------------------------------------------------
    // 4. Status: strict parse accepts exactly the closed vocabulary.
    // ------------------------------------------------------------------

    #[test]
    fn parse_strict_accepts_exactly_the_four_canonical_statuses(s in "\\PC{0,20}") {
        let canonical = matches!(s.as_str(), "online" | "offline" | "maintenance" | "unknown");
        prop_assert_eq!(
            AssetStatus::parse_strict(&s).is_some(),
            canonical,
            "parse_strict divergence on {:?}",
            s
        );
    }

    // ------------------------------------------------------------------
    // 5. Web/API username rule (single predicate for both zones).
    // ------------------------------------------------------------------
    //
    // The web zone gates on `RE_USERNAME` + 3..=50 length after
    // `normalize_username` (via `handlers::web::validate_username_format`,
    // pinned structurally by input_format_pin_test); the API zone gates
    // on `#[validate(length(min=3, max=50), regex(*RE_USERNAME))]`.
    // These properties pin the shared predicate itself: normalization
    // never manufactures acceptance, and acceptance implies the
    // documented charset contract.

    #[test]
    fn username_rule_acceptance_implies_charset_and_bounds(s in "\\PC{0,60}") {
        let normalized = shared::username::normalize_username(&s);
        let accepted =
            (3..=50).contains(&normalized.len()) && RE_USERNAME.is_match(&normalized);
        if accepted {
            prop_assert!(
                normalized
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')),
                "accepted username carries an exotic char: {normalized:?}"
            );
            let first = normalized.as_bytes()[0];
            prop_assert!(first.is_ascii_alphanumeric(), "must start alphanumeric");
        }
    }

    #[test]
    fn username_rule_is_normalization_stable(s in "[a-zA-Z0-9._-]{3,50}") {
        // Normalizing an already-charset-clean string never flips the
        // verdict from accept to reject: the case-insensitive login
        // contract cannot lock a user out of their own account.
        let normalized = shared::username::normalize_username(&s);
        if RE_USERNAME.is_match(&s) {
            prop_assert!(
                RE_USERNAME.is_match(&normalized),
                "normalization broke acceptance: {s:?} -> {normalized:?}"
            );
        }
    }

    // ------------------------------------------------------------------
    // Hostname: acceptance implies the charset contract.
    // ------------------------------------------------------------------

    #[test]
    fn hostname_acceptance_implies_charset(s in "\\PC{0,300}") {
        if is_valid_hostname(&s) {
            prop_assert!(!s.is_empty() && s.len() <= 255);
            prop_assert!(
                s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b':' | b'_' | b'-')),
                "accepted hostname carries an exotic char: {s:?}"
            );
        }
    }
}

/// The icon catalogue is closed and every entry round-trips.
#[test]
fn icon_catalog_round_trips() {
    for icon in ICON_CATALOG {
        assert!(is_valid_icon(icon));
    }
    assert!(!is_valid_icon("rocket"));
    assert!(!is_valid_icon(""));
}

/// The system-reserved virtual slugs stay OUTSIDE the user grammar:
/// nobody can mint a colliding group through the user-facing forms.
#[test]
fn system_virtual_slugs_are_not_user_mintable() {
    for reserved in ["__all-assets__", "__all-iacs-assets__", "__all-secrets__"] {
        assert!(
            !is_valid_slug(reserved),
            "reserved system slug must be rejected by the user grammar: {reserved}"
        );
    }
}
