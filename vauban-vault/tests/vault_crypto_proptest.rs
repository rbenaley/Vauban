//! Property tests for AES-256-GCM encrypt/decrypt primitives.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use aes_gcm::aead::OsRng;
use aes_gcm::{Aes256Gcm, KeyInit};
use proptest::prelude::*;
use vauban_vault::crypto::{CryptoError, decrypt, encrypt};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Round-trip for arbitrary bounded plaintexts.
    #[test]
    fn encrypt_decrypt_roundtrip(
        plaintext in prop::collection::vec(any::<u8>(), 0..1024)
    ) {
        let key = Aes256Gcm::generate_key(&mut OsRng);
        let ct = encrypt(&key, &plaintext).expect("encrypt");
        prop_assert!(ct.len() >= 28);
        let pt = decrypt(&key, &ct).expect("decrypt");
        prop_assert_eq!(pt, plaintext);
    }

    /// Flipping any ciphertext byte fails closed.
    #[test]
    fn flip_byte_fails_decrypt(
        plaintext in prop::collection::vec(any::<u8>(), 0..256),
        idx_seed in any::<usize>(),
    ) {
        let key = Aes256Gcm::generate_key(&mut OsRng);
        let mut ct = encrypt(&key, &plaintext).expect("encrypt");
        prop_assume!(!ct.is_empty());
        let i = idx_seed % ct.len();
        ct[i] ^= 0x01;
        let err = decrypt(&key, &ct).expect_err("tamper");
        prop_assert!(matches!(
            err,
            CryptoError::DecryptionFailed | CryptoError::InvalidCiphertext
        ));
    }

    /// Buffers shorter than nonce+tag are InvalidCiphertext.
    #[test]
    fn short_ciphertext_is_invalid(len in 0usize..28) {
        let key = Aes256Gcm::generate_key(&mut OsRng);
        let data = vec![0u8; len];
        let err = decrypt(&key, &data).unwrap_err();
        prop_assert!(matches!(err, CryptoError::InvalidCiphertext));
    }
}
