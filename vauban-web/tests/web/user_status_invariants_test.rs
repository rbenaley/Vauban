//! Source invariants for the usable-account contract
//! (`is_active && !is_deleted`) and the approval-mail recipient pool.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("parent")
        .to_path_buf()
}

/// Window after `fn <name>` — large enough for the queue / delete
/// helpers, without brace-counting (format! strings break a parser).
fn fn_window<'a>(src: &'a str, name: &str) -> &'a str {
    let needle = format!("fn {name}");
    let start = src
        .find(&needle)
        .unwrap_or_else(|| panic!("missing {name}"));
    let end = src.len().min(start + 20_000);
    &src[start..end]
}

#[test]
fn check_users_usable_filters_lint_passes() {
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("scripts")
        .join("check_users_usable_filters.sh");
    assert!(script.exists(), "missing {}", script.display());
    let out = Command::new("bash")
        .arg(&script)
        .output()
        .unwrap_or_else(|e| panic!("run lint: {e}"));
    assert!(
        out.status.success(),
        "check_users_usable_filters.sh failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn inv_queue_submitted_emails_uses_load_approver_contacts() {
    let src = include_str!("../../src/handlers/web/sessions.rs");
    let body = fn_window(src, "queue_submitted_emails");
    assert!(
        body.contains("load_approver_contacts"),
        "JIT submitted pool must come from load_approver_contacts"
    );
    assert!(
        !body.contains("is_superuser.eq(true)"),
        "JIT submitted must not filter is_superuser alone"
    );
}

#[test]
fn inv_queue_iacs_onboard_uses_load_approver_contacts() {
    let src = include_str!("../../src/handlers/web/iacs.rs");
    let body = fn_window(src, "queue_iacs_onboard_submitted_emails");
    assert!(
        body.contains("load_approver_contacts"),
        "IACS submitted pool must come from load_approver_contacts"
    );
    assert!(
        !body.contains("is_superuser.eq(true)"),
        "IACS submitted must not filter is_superuser alone"
    );
}

#[test]
fn inv_decision_mails_skip_unusable_requester() {
    let jit = fn_window(
        include_str!("../../src/handlers/web/sessions.rs"),
        "queue_approval_email",
    );
    assert!(
        jit.contains("requester_may_receive_mail"),
        "JIT decision mail must skip !usable requesters"
    );

    let iacs_decision = fn_window(
        include_str!("../../src/handlers/web/iacs.rs"),
        "queue_iacs_decision_email",
    );
    assert!(
        iacs_decision.contains("is_deleted.eq(false)"),
        "IACS decision mail must exclude tombstones"
    );
    assert!(
        iacs_decision.contains("is_active.eq(true)"),
        "IACS decision mail must exclude inactive requesters"
    );

    let offboard = fn_window(
        include_str!("../../src/handlers/web/iacs.rs"),
        "queue_iacs_offboarded_email",
    );
    assert!(
        offboard.contains("is_deleted.eq(false)") && offboard.contains("is_active.eq(true)"),
        "IACS offboard mail must skip !usable owners"
    );
}

#[test]
fn inv_ws_admin_pool_is_usable_staff_or_superuser() {
    let src = include_str!("../../src/handlers/web/users.rs");
    let body = fn_window(src, "broadcast_admin_sessions_update");
    assert!(
        body.contains("is_staff.eq(true).or(users::is_superuser.eq(true))"),
        "WS admin pool must be staff ∪ superuser"
    );
    assert!(
        body.contains("is_active.eq(true)"),
        "WS admin pool must require is_active"
    );
    assert!(
        body.contains("is_deleted.eq(false)"),
        "WS admin pool must exclude tombstones"
    );
}

#[test]
fn inv_delete_user_sets_inactive_and_revokes() {
    let src = include_str!("../../src/handlers/web/users.rs");
    let body = fn_window(src, "delete_user_web");
    assert!(
        body.contains("users::is_active.eq(false)"),
        "soft-delete SET must include is_active=false"
    );
    assert!(
        body.contains("users::is_deleted.eq(true)"),
        "soft-delete SET must include is_deleted=true"
    );
    assert!(
        body.contains("deactivate_user(") && body.contains("\"account_deleted\""),
        "delete_user_web must call deactivate_user with account_deleted"
    );
}

#[test]
fn inv_migration_tombstone_check_and_backfill() {
    let up = include_str!(
        "../../../vauban-db/migrations/20260815000000_users_tombstone_inactive/up.sql"
    );
    assert!(
        up.contains("users_tombstone_is_inactive"),
        "up.sql must name CHECK users_tombstone_is_inactive"
    );
    assert!(
        up.contains("CHECK (NOT is_deleted OR NOT is_active)"),
        "CHECK must forbid active tombstones"
    );
    assert!(
        up.contains("SET is_active = false") && up.contains("WHERE is_deleted AND is_active"),
        "up.sql must backfill leftover active tombstones"
    );

    let down = include_str!(
        "../../../vauban-db/migrations/20260815000000_users_tombstone_inactive/down.sql"
    );
    assert!(
        down.contains("DROP CONSTRAINT IF EXISTS users_tombstone_is_inactive"),
        "down.sql must drop the CHECK only"
    );
    assert!(
        !down.to_ascii_lowercase().contains("is_active = true"),
        "down.sql must not reactivate tombstones"
    );
}

#[test]
fn inv_session_verify_filters_usable_on_both_branches() {
    let src = include_str!("../../src/middleware/auth.rs");
    let body = fn_window(src, "verify_session_with_timeouts");
    let active = body.matches("users::is_active.eq(true)").count();
    let deleted = body.matches("users::is_deleted.eq(false)").count();
    assert_eq!(
        active, 2,
        "jti + token_hash branches must each filter is_active"
    );
    assert_eq!(
        deleted, 2,
        "jti + token_hash branches must each filter !is_deleted"
    );
}

#[test]
fn inv_api_key_lookup_filters_usable_owner() {
    let src = include_str!("../../src/middleware/api_key.rs");
    assert!(
        src.contains("users::is_active.eq(true)"),
        "API key auth must require an active owner"
    );
    assert!(
        src.contains("users::is_deleted.eq(false)"),
        "API key auth must deny tombstone owners"
    );
}

#[test]
fn inv_login_filters_deleted_then_inactive() {
    let src = include_str!("../../src/handlers/auth.rs");
    let body = fn_window(src, "login");
    assert!(
        body.contains("is_deleted.eq(false)"),
        "login lookup must exclude tombstones"
    );
    assert!(
        body.contains("!user.is_active"),
        "login must refuse inactive accounts after credential check"
    );
}

#[test]
fn inv_user_status_module_is_exported() {
    let src = include_str!("../../src/services/mod.rs");
    assert!(
        src.contains("pub mod user_status"),
        "user_status must be a public services module"
    );
    let helper = include_str!("../../src/services/user_status.rs");
    assert!(helper.contains("pub fn is_usable"));
    assert!(helper.contains("pub async fn load_approver_contacts"));
    assert!(helper.contains("pub fn tombstone_flags_legal"));
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(64))]

    #[test]
    fn session_admit_iff_usable(active in proptest::bool::ANY, deleted in proptest::bool::ANY) {
        let admit = vauban_web::services::user_status::is_usable(active, deleted);
        proptest::prop_assert_eq!(admit, active && !deleted);
    }

    #[test]
    fn tombstone_row_legal_iff_check(
        deleted in proptest::bool::ANY,
        active in proptest::bool::ANY,
    ) {
        proptest::prop_assert_eq!(
            vauban_web::services::user_status::tombstone_flags_legal(deleted, active),
            !deleted || !active
        );
    }
}

#[test]
fn battle_usable_predicate_under_contention() {
    use std::sync::{Arc, Barrier};
    use std::thread;

    let barrier = Arc::new(Barrier::new(8));
    let mut handles = Vec::new();
    for t in 0..8 {
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for i in 0..128 {
                let active = (i + t) % 2 == 0;
                let deleted = i % 3 == 0;
                assert_eq!(
                    vauban_web::services::user_status::is_usable(active, deleted),
                    active && !deleted
                );
            }
        }));
    }
    for h in handles {
        h.join().expect("battle thread");
    }
}

#[test]
fn lint_script_lives_next_to_mailer_lints() {
    let script = repo_root().join("vauban-web/scripts/check_users_usable_filters.sh");
    assert!(script.exists(), "{}", script.display());
}
