//! Property tests for the hybrid KEM / signature public API.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use proptest::prelude::*;
use vauban_web::crypto::{
    HybridKemSecretKey, HybridSigSecretKey, combine_shared_secrets, constant_time_compare,
};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    #[test]
    fn prop_hybrid_sign_verify_roundtrip(msg in prop::collection::vec(any::<u8>(), 0..256)) {
        let (pk, sk) = HybridSigSecretKey::generate();
        let sig = sk.sign(&msg);
        prop_assert!(pk.verify(&msg, &sig).is_ok());
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(8))]

    #[test]
    fn prop_hybrid_kem_encapsulate_matches_decapsulate(_seed in any::<u8>()) {
        let (pk, sk) = HybridKemSecretKey::generate();
        let (send, ct) = pk.encapsulate().expect("encapsulate");
        let recv = sk.decapsulate(&ct).expect("decapsulate");
        prop_assert_eq!(send, recv);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn prop_hkdf_identical_for_same_ikm(
        classical in prop::array::uniform32(any::<u8>()),
        pq in prop::array::uniform32(any::<u8>()),
    ) {
        let a = combine_shared_secrets(&classical, &pq).expect("hkdf");
        let b = combine_shared_secrets(&classical, &pq).expect("hkdf");
        prop_assert!(constant_time_compare(&a, &b));
    }
}
