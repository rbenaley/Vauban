//! Any Ed25519 key other than the pin is rejected on a self-consistent seal.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::Cursor;

use ed25519_dalek::SigningKey;
use proptest::prelude::*;
use vauban_audit::worm::{
    AuditRecord, GENESIS_HASH, VerifyError, WormLog, parse_pinned_verifying_key, verify_reader,
};

fn event() -> AuditRecord {
    AuditRecord {
        timestamp: 1_700_000_000,
        event_type: "AuthFailure".to_string(),
        user_id: Some("u".to_string()),
        session_id: None,
        source_ip: None,
        details: "x".to_string(),
    }
}

fn sealed_with(seed: [u8; 32]) -> Vec<u8> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("seg.jsonl");
    let file = std::fs::File::create(&path).unwrap();
    let mut log = WormLog::new(file, "seg-0".to_string(), GENESIS_HASH, 0);
    log.append_event(&event()).unwrap();
    log.seal(&SigningKey::from_bytes(&seed), 1).unwrap();
    drop(log);
    std::fs::read(&path).unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn alien_seed_is_always_pubkey_mismatch(alien_byte in 1u8..=255) {
        let pin_seed = [7u8; 32];
        let mut alien = [alien_byte; 32];
        if alien == pin_seed {
            alien[0] = alien_byte.wrapping_add(1);
        }
        let bytes = sealed_with(alien);
        let pin = SigningKey::from_bytes(&pin_seed).verifying_key();
        let err = verify_reader(Cursor::new(bytes), GENESIS_HASH, 0, &pin).unwrap_err();
        prop_assert!(
            matches!(err, VerifyError::PubkeyMismatch { .. }),
            "got {:?}",
            err
        );
    }

    #[test]
    fn hex_round_trips_pinned_key(seed in prop::array::uniform32(0u8..=255)) {
        let vk = SigningKey::from_bytes(&seed).verifying_key();
        let hex_s = hex::encode(vk.to_bytes());
        prop_assert_eq!(parse_pinned_verifying_key(&hex_s).unwrap(), vk);
    }
}
