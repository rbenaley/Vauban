//! Property + battle tests: Keyring::encrypt always yields a vault envelope (I5).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use proptest::prelude::*;
use std::sync::{Arc, Barrier};
use std::thread;
use vauban_vault::keyring::{Keyring, MasterKey, is_encrypted};

fn test_master_key() -> MasterKey {
    MasterKey::from_bytes([
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ])
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// I5: every encrypt output satisfies the shared shape predicate.
    #[test]
    fn encrypt_output_is_always_vault_envelope(plaintext in prop::collection::vec(any::<u8>(), 0..128)) {
        let mk = test_master_key();
        let kr = Keyring::new(mk.as_bytes(), "mfa", 1);
        let ct = kr.encrypt(&plaintext).expect("encrypt");
        prop_assert!(
            is_encrypted(&ct),
            "encrypt produced non-envelope: {ct:?}"
        );
        prop_assert!(shared::vault_envelope::is_vault_envelope(&ct));
        let round = kr.decrypt(&ct).expect("decrypt");
        prop_assert_eq!(round.as_slice(), plaintext.as_slice());
    }
}

/// Battle: concurrent encrypt / classify / decrypt under contention.
#[test]
fn battle_concurrent_encrypt_classify_decrypt() {
    let mk = test_master_key();
    let kr = Arc::new(Keyring::new(mk.as_bytes(), "credentials", 1));
    let n = 8usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);
    for i in 0..n {
        let kr = Arc::clone(&kr);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            let plain = format!("secret-{i}").into_bytes();
            let ct = kr.encrypt(&plain).expect("encrypt");
            assert!(is_encrypted(&ct));
            assert!(shared::vault_envelope::is_vault_envelope(&ct));
            let back = kr.decrypt(&ct).expect("decrypt");
            assert_eq!(back, plain);
        }));
    }
    for h in handles {
        h.join().expect("thread");
    }
}
