//! Property tests for vault envelope shape detection (I1 / I3 / I4).

use proptest::prelude::*;
use shared::vault_envelope::{is_vault_envelope, vault_envelope_version};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Classifier never panics and is deterministic (pure).
    #[test]
    fn is_vault_envelope_is_pure_and_panic_free(s in ".*") {
        let a = is_vault_envelope(&s);
        let b = is_vault_envelope(&s);
        prop_assert_eq!(a, b);
    }

    /// Well-formed grammar always classifies as envelope.
    #[test]
    fn well_formed_envelope_is_accepted(
        digits in "[0-9]{1,6}",
        payload in ".{1,64}",
    ) {
        let s = format!("v{digits}:{payload}");
        prop_assert!(is_vault_envelope(&s), "rejected well-formed {s:?}");
        let v: u32 = digits.parse().unwrap();
        prop_assert_eq!(vault_envelope_version(&s), Some(v));
    }

    /// Empty payload after colon is never an envelope (I3).
    #[test]
    fn empty_payload_is_rejected(digits in "[0-9]{1,6}") {
        let s = format!("v{digits}:");
        prop_assert!(!is_vault_envelope(&s));
        prop_assert_eq!(vault_envelope_version(&s), None);
    }

    /// Missing colon / non-digit version / missing v prefix reject (I4).
    #[test]
    fn lookalikes_are_rejected(
        body in "[A-Za-z2-7]{8,32}",
    ) {
        // Raw base32-ish TOTP secrets (issue #11 regression).
        prop_assume!(!body.starts_with('v') || !body.contains(':'));
        prop_assert!(!is_vault_envelope(&body));
        let no_version = format!("v:{body}");
        let non_digit = format!("va:{body}");
        let no_colon = format!("v1{body}");
        prop_assert!(!is_vault_envelope(&no_version));
        prop_assert!(!is_vault_envelope(&non_digit));
        prop_assert!(!is_vault_envelope(&no_colon));
    }
}
