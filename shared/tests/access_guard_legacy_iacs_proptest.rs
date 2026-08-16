//! Property tests for [`shared::access_guard::expand_legacy_all_iacs_protocols`].

#![allow(clippy::expect_used, clippy::unwrap_used)]

use proptest::prelude::*;
use shared::access_guard::{
    IACS_APPLICATIVE_PROTOCOLS, IACS_LEGACY_ALL_PROTOCOLS, PROTOCOL_IACS_TUNNEL,
    expand_legacy_all_iacs_protocols, is_iacs_applicative_protocol, is_legacy_all_iacs_rule,
    rule_grants_asset_type,
};

fn protocol_token() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("ssh".to_string()),
        Just("rdp".to_string()),
        Just("iacs_modbus".to_string()),
        Just("iacs_opcua".to_string()),
        Just("iacs_profinet".to_string()),
        Just("iacs_iec104".to_string()),
        Just("iacs_enip".to_string()),
        Just("iacs_bacnet_sc".to_string()),
        Just("iacs_dnp3".to_string()),
        Just("iacs_iec61850".to_string()),
        Just("iacs_tcp".to_string()),
        Just("vnc".to_string()),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Expansion never drops a token the caller already had.
    #[test]
    fn expand_legacy_never_drops_existing(
        protocols in prop::collection::vec(protocol_token(), 0..16)
    ) {
        let expanded = expand_legacy_all_iacs_protocols(&protocols);
        for p in &protocols {
            prop_assert!(expanded.iter().any(|q| q == p));
        }
    }

    /// A set that is not the pre-ADR-006 snapshot is returned unchanged.
    #[test]
    fn expand_legacy_is_identity_unless_legacy_all(
        protocols in prop::collection::vec(protocol_token(), 0..12)
    ) {
        let expanded = expand_legacy_all_iacs_protocols(&protocols);
        if is_legacy_all_iacs_rule(&protocols) {
            for p in IACS_APPLICATIVE_PROTOCOLS {
                prop_assert!(expanded.iter().any(|q| q == *p));
            }
        } else {
            prop_assert_eq!(expanded, protocols);
        }
    }

    /// Applying the helper twice is a no-op after the first pass.
    #[test]
    fn expand_legacy_is_idempotent(
        extra in prop::collection::vec(protocol_token(), 0..8)
    ) {
        let mut first: Vec<String> = IACS_LEGACY_ALL_PROTOCOLS
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        first.extend(extra);
        let once = expand_legacy_all_iacs_protocols(&first);
        let twice = expand_legacy_all_iacs_protocols(&once);
        prop_assert_eq!(once, twice);
    }

    /// Prefix helper and rule_grants stay aligned: a future iacs_*
    /// token is granted iff the rule is the durable all-IACS snapshot.
    #[test]
    fn rule_grants_future_token_only_when_legacy_all(
        extra in prop::collection::vec(protocol_token(), 0..8),
        future in "[a-z]{1,12}"
    ) {
        let future_token = format!("iacs_{future}");
        prop_assume!(future_token != PROTOCOL_IACS_TUNNEL);
        prop_assert!(is_iacs_applicative_protocol(&future_token));

        let mut protocols = extra;
        let granted_partial = rule_grants_asset_type(&protocols, &future_token);
        if is_legacy_all_iacs_rule(&protocols) {
            prop_assert!(granted_partial);
        } else {
            prop_assert_eq!(granted_partial, protocols.iter().any(|p| p == &future_token));
        }

        protocols.extend(IACS_LEGACY_ALL_PROTOCOLS.iter().map(|s| (*s).to_string()));
        prop_assert!(rule_grants_asset_type(&protocols, &future_token));
        prop_assert!(!rule_grants_asset_type(&protocols, PROTOCOL_IACS_TUNNEL));
    }
}
