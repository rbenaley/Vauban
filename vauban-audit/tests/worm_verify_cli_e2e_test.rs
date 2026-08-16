//! Drive the `vauban-audit verify` binary: missing pin, alien pin, good pin.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;
use std::process::Command;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::SigningKey;
use vauban_audit::worm::{AuditRecord, GENESIS_HASH, WormLog};

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_vauban-audit"))
}

fn write_sealed_segment(dir: &std::path::Path, seed: [u8; 32]) -> std::path::PathBuf {
    let seg = dir.join("seg.jsonl");
    let file = fs::File::create(&seg).unwrap();
    let mut log = WormLog::new(file, "seg-0".to_string(), GENESIS_HASH, 0);
    log.append_event(&AuditRecord {
        timestamp: 1,
        event_type: "AuthFailure".to_string(),
        user_id: None,
        session_id: None,
        source_ip: None,
        details: "cli".to_string(),
    })
    .unwrap();
    log.seal(&SigningKey::from_bytes(&seed), 2).unwrap();
    drop(log);
    seg
}

#[test]
fn verify_without_pubkey_exits_2() {
    let out = bin().args(["verify", "missing.jsonl"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--pubkey"), "{stderr}");
}

#[test]
fn verify_wrong_key_exits_2() {
    let dir = tempfile::tempdir().unwrap();
    let seg = write_sealed_segment(dir.path(), [7u8; 32]);
    let alien = dir.path().join("alien.pub");
    fs::write(
        &alien,
        BASE64.encode(
            SigningKey::from_bytes(&[9u8; 32])
                .verifying_key()
                .to_bytes(),
        ),
    )
    .unwrap();
    let out = bin()
        .args([
            "verify",
            "--pubkey",
            alien.to_str().unwrap(),
            seg.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("TAMPER") || stderr.contains("public key"),
        "{stderr}"
    );
}

#[test]
fn verify_matching_key_exits_0() {
    let dir = tempfile::tempdir().unwrap();
    let seed = [7u8; 32];
    let seg = write_sealed_segment(dir.path(), seed);
    let pub_path = dir.path().join("signing_key.pub");
    fs::write(
        &pub_path,
        BASE64.encode(SigningKey::from_bytes(&seed).verifying_key().to_bytes()),
    )
    .unwrap();
    let out = bin()
        .args([
            "verify",
            "--pubkey",
            pub_path.to_str().unwrap(),
            seg.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("OK:"));
}
