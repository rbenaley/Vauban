//! Property tests for [`shared::username::normalize_username`].

#![allow(clippy::expect_used, clippy::unwrap_used)]

use proptest::prelude::*;
use shared::username::normalize_username;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Normalization is idempotent for arbitrary Unicode strings.
    #[test]
    fn normalize_is_idempotent(s in ".*") {
        let once = normalize_username(&s);
        let twice = normalize_username(&once);
        prop_assert_eq!(once, twice);
    }

    /// Matches the documented oracle: trim then lowercase.
    #[test]
    fn trim_then_lower_matches_oracle(s in ".*") {
        let expected = s.trim().to_lowercase();
        prop_assert_eq!(normalize_username(&s), expected);
    }

    /// ASCII alpha case variants of a body collapse to the same value.
    #[test]
    fn case_fold_collapses_ascii_alpha(
        body in "[A-Za-z0-9._-]{1,64}",
        pad_l in " {0,4}",
        pad_r in " {0,4}",
    ) {
        let mixed = format!("{pad_l}{body}{pad_r}");
        let upper = format!("{pad_l}{}{pad_r}", body.to_uppercase());
        let lower = format!("{pad_l}{}{pad_r}", body.to_lowercase());
        let a = normalize_username(&mixed);
        let b = normalize_username(&upper);
        let c = normalize_username(&lower);
        prop_assert_eq!(&a, &b);
        prop_assert_eq!(&a, &c);
        prop_assert_eq!(a, body.to_lowercase());
    }

    /// Non-alpha structure (`.`, `_`, `-`, digits) survives case-fold.
    #[test]
    fn preserves_non_alpha_structure(
        s in "[A-Za-z0-9._-]{1,64}"
    ) {
        let out = normalize_username(&s);
        for (i, ch) in s.chars().enumerate() {
            if !ch.is_ascii_alphabetic() {
                let out_ch = out.chars().nth(i);
                prop_assert_eq!(
                    out_ch,
                    Some(ch),
                    "index {} changed {:?}",
                    i,
                    ch
                );
            }
        }
    }
}
