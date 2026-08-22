//! E2E: hybrid KEM + signature via the public `vauban_web::crypto` API only.
//!
//! This is the product seam for Lot A: no second encode/decode path, no
//! pqcrypto types, no private helpers.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use vauban_web::crypto::{
    HybridKemSecretKey, HybridSigSecretKey, ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SIGNATURE_BYTES,
    ML_KEM_768_CIPHERTEXT_BYTES, ML_KEM_768_PUBLIC_KEY_BYTES, ML_KEM_768_SEED_BYTES,
    combine_shared_secrets, constant_time_compare, constant_time_compare_str,
};

#[test]
fn e2e_hybrid_kem_round_trip_via_public_api() {
    let (pk, sk) = HybridKemSecretKey::generate();
    assert_eq!(pk.pq_public_key_len(), ML_KEM_768_PUBLIC_KEY_BYTES);
    assert_eq!(sk.pq_secret_key_len(), ML_KEM_768_SEED_BYTES);

    let (send, ct) = pk.encapsulate().expect("encapsulate");
    assert_eq!(ct.pq_ciphertext_len(), ML_KEM_768_CIPHERTEXT_BYTES);
    let recv = sk.decapsulate(&ct).expect("decapsulate");
    assert_eq!(send, recv);
    assert!(!constant_time_compare(&send, &[0u8; 32]));
}

#[test]
fn e2e_hybrid_signature_round_trip_via_public_api() {
    let (pk, sk) = HybridSigSecretKey::generate();
    let message = b"vauban hybrid pqc e2e";
    let sig = sk.sign(message);
    assert_eq!(pk.pq_public_key_len(), ML_DSA_65_PUBLIC_KEY_BYTES);
    assert_eq!(sig.pq_signature_len(), ML_DSA_65_SIGNATURE_BYTES);
    pk.verify(message, &sig).expect("verify");
}

#[test]
fn e2e_hkdf_label_stays_deterministic_on_public_combine() {
    let a = combine_shared_secrets(&[9u8; 32], &[8u8; 32]).expect("hkdf");
    let b = combine_shared_secrets(&[9u8; 32], &[8u8; 32]).expect("hkdf");
    assert!(constant_time_compare(&a, &b));
    assert!(constant_time_compare_str("ok", "ok"));
}
