//! Concurrent `verify_reader` against the same pinned key.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::Cursor;
use std::sync::{Arc, Barrier};
use std::thread;

use ed25519_dalek::SigningKey;
use vauban_audit::worm::{AuditRecord, GENESIS_HASH, WormLog, verify_reader};

#[test]
fn battle_verify_reader_shared_pin() {
    let seed = [7u8; 32];
    let key = SigningKey::from_bytes(&seed);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("seg.jsonl");
    let file = std::fs::File::create(&path).unwrap();
    let mut log = WormLog::new(file, "seg-0".to_string(), GENESIS_HASH, 0);
    log.append_event(&AuditRecord {
        timestamp: 1,
        event_type: "AuthFailure".to_string(),
        user_id: None,
        session_id: None,
        source_ip: None,
        details: "x".to_string(),
    })
    .unwrap();
    log.seal(&key, 2).unwrap();
    drop(log);
    let bytes = Arc::new(std::fs::read(&path).unwrap());
    let pin = Arc::new(key.verifying_key());

    const N: usize = 8;
    let barrier = Arc::new(Barrier::new(N));
    let mut handles = Vec::with_capacity(N);
    for _ in 0..N {
        let barrier = Arc::clone(&barrier);
        let bytes = Arc::clone(&bytes);
        let pin = Arc::clone(&pin);
        handles.push(thread::spawn(move || {
            barrier.wait();
            let report =
                verify_reader(Cursor::new(bytes.as_slice()), GENESIS_HASH, 0, &pin).unwrap();
            assert_eq!(report.seals, 1);
        }));
    }
    for h in handles {
        h.join().expect("worker panicked");
    }
}
