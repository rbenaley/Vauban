//! Structural pins: every security-relevant web seam emits a typed audit
//! event. These greps are the cheap, always-on guard that a future refactor
//! does not silently drop an `emit_audit` / `emit_audit_critical` call and
//! re-mute `vauban-web` (the pre-fix state where the only audit trace was an
//! Apache-style `tracing` line and no `AuditEvent` ever reached the WORM log).
//!
//! Behavioral coverage of the client itself lives in
//! `vauban-web/src/ipc/audit.rs` (`mod tests`); the durable persistence is
//! covered by `vauban-audit`. Here we only assert the wiring is present at
//! each documented seam.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::PathBuf;

fn src(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// Assert `file` references every needle (the emitter + each expected event
/// variant for that seam).
fn assert_seam(rel: &str, needles: &[&str]) {
    let body = src(rel);
    for needle in needles {
        assert!(
            body.contains(needle),
            "{rel} must reference `{needle}` -- the audit seam is missing or \
             was refactored away. Re-wire emit_audit/emit_audit_critical."
        );
    }
}

#[test]
fn audit_helper_module_exists() {
    let body = src("services/audit.rs");
    assert!(body.contains("pub fn emit_audit"));
    assert!(body.contains("pub async fn emit_audit_critical"));
    // The AppState field must be wired so the helpers can reach the client.
    assert!(src("lib.rs").contains("audit_client: Option<Arc<ipc::AuditClient>>"));
}

#[test]
fn audit_client_module_exists() {
    let body = src("ipc/audit.rs");
    for needle in [
        "pub struct AuditClient",
        "pub fn emit",
        "pub async fn emit_critical",
        "AuditAck",
        "AuditNack",
        "pub const CRITICAL_ACK_TIMEOUT_SECS: u64 = 5",
        "audit ack timed out",
    ] {
        assert!(
            body.contains(needle),
            "ipc/audit.rs must reference `{needle}`"
        );
    }
    // Wired into main and spawned.
    assert!(src("main.rs").contains("init_audit_client"));
    assert!(src("main.rs").contains("Audit IPC processing task"));
}

#[test]
fn auth_seam_is_instrumented() {
    assert_seam(
        "handlers/auth.rs",
        &[
            "emit_audit",
            "AuditEventType::AuthFailure",
            "AuditEventType::AuthSuccess",
            "AuditEventType::Logout",
            "AuditEventType::MfaEnrolled",
            "AuditEventType::MfaChallengePassed",
            "AuditEventType::MfaChallengeFailed",
            "AuditEventType::MfaSecretGenerated",
        ],
    );
    // The privileged elevation (MFA pass + API login) must be fail-closed.
    assert!(src("handlers/auth.rs").contains("emit_audit_critical"));
}

#[test]
fn users_seam_is_instrumented() {
    assert_seam(
        "handlers/web/users.rs",
        &[
            "AuditEventType::UserCreated",
            "AuditEventType::UserUpdated",
            "AuditEventType::UserDeleted",
            "AuditEventType::RoleChanged",
            "AuditEventType::PasswordChanged",
        ],
    );
    // Role change + deletion are escalation/destructive -> critical.
    assert!(src("handlers/web/users.rs").contains("emit_audit_critical"));
}

#[test]
fn policy_seams_are_instrumented() {
    assert_seam(
        "handlers/web/access_rules.rs",
        &[
            "AuditEventType::AccessRuleCreated",
            "AuditEventType::AccessRuleUpdated",
            "AuditEventType::AccessRuleDeleted",
        ],
    );
    assert_seam(
        "handlers/web/groups.rs",
        &[
            "AuditEventType::GroupCreated",
            "AuditEventType::GroupUpdated",
            "AuditEventType::GroupDeleted",
            "AuditEventType::GroupMemberAdded",
            "AuditEventType::GroupMemberRemoved",
        ],
    );
    assert_seam(
        "handlers/web/asset_groups.rs",
        &[
            "AuditEventType::AssetGroupCreated",
            "AuditEventType::AssetGroupUpdated",
            "AuditEventType::AssetGroupDeleted",
            "AuditEventType::AssetGroupMemberAdded",
            "AuditEventType::AssetGroupMemberRemoved",
        ],
    );
}

#[test]
fn assets_seams_are_instrumented() {
    assert_seam(
        "handlers/web/manage_assets.rs",
        &[
            "AuditEventType::AssetCreated",
            "AuditEventType::AssetUpdated",
            "AuditEventType::AssetDeleted",
        ],
    );
    assert_seam(
        "handlers/api/manage_assets.rs",
        &[
            "AuditEventType::AssetCreated",
            "AuditEventType::AssetUpdated",
        ],
    );
}

#[test]
fn sessions_and_approvals_seams_are_instrumented() {
    assert_seam(
        "handlers/web/sessions.rs",
        &[
            "AuditEventType::ApprovalRequested",
            "AuditEventType::ApprovalGranted",
            "AuditEventType::ApprovalDenied",
            "AuditEventType::ApprovalCancelled",
        ],
    );
    assert_seam("handlers/web/ssh.rs", &["AuditEventType::SessionRequested"]);
    assert_seam("handlers/web/rdp.rs", &["AuditEventType::SessionRequested"]);
    assert_seam(
        "handlers/api/sessions.rs",
        &["AuditEventType::SessionTerminated"],
    );
}

#[test]
fn central_denial_seams_emit_access_denied() {
    assert_seam(
        "services/session_access.rs",
        &["AuditEventType::AccessDenied"],
    );
    assert_seam("auth/step_up.rs", &["AuditEventType::AccessDenied"]);
}
