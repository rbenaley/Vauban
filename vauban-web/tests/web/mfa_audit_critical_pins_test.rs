//! Source pins: MFA escalation stays fail-closed on durable audit ACK.
//!
//! Complements `audit_instrumentation_test` with ordering / error-string
//! invariants specific to the FreeBSD staging regression
//! (`audit ack timed out` → HTTP 500 on POST `/mfa/verify`).

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::PathBuf;
use vauban_web::ipc::audit::CRITICAL_ACK_TIMEOUT_SECS;

fn src(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

#[test]
fn inv_critical_ack_timeout_is_five_seconds() {
    assert_eq!(CRITICAL_ACK_TIMEOUT_SECS, 5);
    let audit = src("ipc/audit.rs");
    assert!(audit.contains("pub const CRITICAL_ACK_TIMEOUT_SECS: u64 = 5"));
    assert!(audit.contains("audit ack timed out"));
}

#[test]
fn inv_mfa_challenge_passed_is_fail_closed_before_token_mint() {
    let auth = src("handlers/auth.rs");
    let mfa = auth
        .find("AuditEventType::MfaChallengePassed")
        .expect("MfaChallengePassed");
    // emit_audit_critical appears in the lookback window before the variant.
    let lookback = &auth[mfa.saturating_sub(400)..mfa];
    assert!(
        lookback.contains("emit_audit_critical"),
        "MfaChallengePassed must be inside emit_audit_critical"
    );
    let after = &auth[mfa..mfa.saturating_add(800).min(auth.len())];
    let mint = after
        .find("true, // mfa_verified")
        .expect("mfa_verified mint after challenge");
    let between = &after[..mint];
    assert!(
        between.contains("audit emit failed") || lookback.contains("audit emit failed") || {
            // map_err sits between emit await and mint
            after[..mint].contains("map_err")
        },
        "critical failure must fail the handler closed before mint"
    );
    // The await + map_err must complete before the mint marker.
    assert!(
        after[..mint].contains(".await"),
        "emit_audit_critical must be awaited before minting mfa_verified token"
    );
}

#[test]
fn inv_mfa_challenge_failed_is_fire_and_forget() {
    // Failed challenges must NOT block the user behind a durable ack
    // (only the successful escalation is fail-closed).
    let auth = src("handlers/auth.rs");
    let failed = auth
        .find("AuditEventType::MfaChallengeFailed")
        .expect("MfaChallengeFailed");
    let window = &auth[failed.saturating_sub(300)..failed.saturating_add(200)];
    assert!(
        window.contains("emit_audit(") || window.contains("emit_audit\n"),
        "MfaChallengeFailed should use fire-and-forget emit_audit"
    );
    assert!(
        !window.contains("emit_audit_critical"),
        "MfaChallengeFailed must not use emit_audit_critical"
    );
}

#[test]
fn inv_process_incoming_spawned_for_audit_client() {
    let main = src("main.rs");
    assert!(main.contains("Audit IPC processing task"));
    assert!(main.contains("process_incoming"));
    assert!(main.contains("init_audit_client"));
}
