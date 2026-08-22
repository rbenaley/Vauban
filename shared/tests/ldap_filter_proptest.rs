//! Property tests: RFC 4515 specials never open a second filter clause.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use proptest::prelude::*;
use shared::ldap_filter::{FilterEncodeError, equality_filter};

fn rfc4515_specials() -> impl Strategy<Value = char> {
    prop_oneof![Just('*'), Just('('), Just(')'), Just('\\'), Just('\0')]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Embedding a special in an otherwise-plain value never yields raw
    /// `(` / `)` inside the assertion -- only the wrapping pair remains.
    #[test]
    fn specials_are_encoded_as_literals(
        prefix in "[A-Za-z0-9=,]{0,12}",
        special in rfc4515_specials(),
        suffix in "[A-Za-z0-9=,]{0,12}",
    ) {
        let value = format!("{prefix}{special}{suffix}");
        let filter = equality_filter("member", &value).expect("ASCII");
        prop_assert!(filter.starts_with("(member="));
        prop_assert!(filter.ends_with(')'));
        prop_assert_eq!(filter.chars().filter(|c| *c == '(').count(), 1);
        prop_assert_eq!(filter.chars().filter(|c| *c == ')').count(), 1);
        prop_assert!(!filter[1..filter.len() - 1].contains('('));
        prop_assert!(!filter[1..filter.len() - 1].contains(')'));
    }

    /// A value that is already a second-clause injection stays one clause.
    #[test]
    fn injection_shape_stays_one_clause(
        ident in "[A-Za-z][A-Za-z0-9]{0,12}",
    ) {
        let value = format!("{ident})(uid=admin");
        let filter = equality_filter("uniqueMember", &value).expect("ASCII");
        prop_assert!(!filter.contains(")("));
        prop_assert!(filter.contains("\\29\\28"));
    }

    /// Non-ASCII and C0 controls (other than NUL, which is escaped) refuse.
    #[test]
    fn illegal_bytes_are_rejected(
        prefix in "[A-Za-z]{1,6}",
        bad in prop_oneof![Just('\n'), Just('\t'), Just('\u{7f}'), Just('é')],
    ) {
        let value = format!("{prefix}{bad}");
        prop_assert_eq!(
            equality_filter("member", &value),
            Err(FilterEncodeError::IllegalValue)
        );
    }
}
