//! Source invariants for policy eval 3→2 on SSH/RDP session-open.
//!
//! Companion of `scripts/check_policy_eval_session_open.sh` and
//! `docs/runbooks/policy_eval_session_open_smoke_test.md`.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::PathBuf;
use std::process::Command;

const SSH: &str = include_str!("../../src/handlers/web/ssh.rs");
const RDP: &str = include_str!("../../src/handlers/web/rdp.rs");
const SESSIONS: &str = include_str!("../../src/handlers/web/sessions.rs");
const ACCESS_IPC: &str = include_str!("../../src/ipc/access.rs");
const ACCESS_HANDLER: &str = include_str!("../../../vauban-access/src/handlers.rs");

fn script_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("scripts")
        .join("check_policy_eval_session_open.sh")
}

fn assert_mint_before_insert(name: &str, src: &str) {
    let mint = src
        .find(".issue_session_token(")
        .unwrap_or_else(|| panic!("{name}: must call issue_session_token"));
    let insert = src
        .find("insert_into(proxy_sessions")
        .unwrap_or_else(|| panic!("{name}: must INSERT proxy_sessions"));
    assert!(
        mint < insert,
        "{name}: issue_session_token (byte {mint}) must precede \
         insert_into(proxy_sessions) (byte {insert})"
    );
    let count = src.matches(".issue_session_token(").count();
    assert_eq!(
        count, 1,
        "{name}: expected exactly one issue_session_token, found {count}"
    );
    assert!(
        !src.contains("can_access_asset("),
        "{name}: must not call can_access_asset (constraints from SessionTokenIssued)"
    );
}

#[test]
fn inv_connect_ssh_mint_before_insert_no_can_access() {
    assert_mint_before_insert("connect_ssh", SSH);
}

#[test]
fn inv_connect_rdp_mint_before_insert_no_can_access() {
    assert_mint_before_insert("connect_rdp", RDP);
}

#[test]
fn inv_submit_access_request_keeps_can_access_asset() {
    assert!(
        SESSIONS.contains("can_access_asset"),
        "submit_access_request path must keep can_access_asset"
    );
}

#[test]
fn inv_issued_session_token_struct_and_client() {
    assert!(ACCESS_IPC.contains("struct IssuedSessionToken"));
    assert!(ACCESS_IPC.contains("require_mfa"));
    assert!(ACCESS_IPC.contains("require_approval"));
    assert!(ACCESS_IPC.contains("max_session_duration"));
    assert!(ACCESS_IPC.contains("pub async fn issue_session_token("));
}

#[test]
fn inv_handle_issue_session_token_propagates_constraints() {
    let start = ACCESS_HANDLER
        .find("fn handle_issue_session_token")
        .expect("handle_issue_session_token");
    let body = &ACCESS_HANDLER[start..start.saturating_add(4_000).min(ACCESS_HANDLER.len())];
    for field in ["require_mfa", "require_approval", "max_session_duration"] {
        assert!(
            body.contains(field),
            "handle_issue_session_token must propagate {field}"
        );
    }
    assert!(body.contains("SessionTokenIssued"));
}

#[test]
fn check_policy_eval_session_open_lint_passes() {
    let script = script_path();
    assert!(script.exists(), "missing {}", script.display());
    let out = Command::new("bash")
        .arg(&script)
        .output()
        .expect("run lint");
    assert!(
        out.status.success(),
        "check_policy_eval_session_open.sh failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
