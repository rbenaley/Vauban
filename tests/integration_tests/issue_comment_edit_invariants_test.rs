//! Source-shape invariants for Support comment edit.

use std::process::Command;

#[test]
fn inv_check_issue_comment_edit_script() {
    let output = Command::new("bash")
        .arg("scripts/check_issue_comment_edit.sh")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run check_issue_comment_edit.sh");
    assert!(
        output.status.success(),
        "scripts/check_issue_comment_edit.sh failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn inv_admin_only_edit_surface() {
    let admin = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/issues/issue_key.rs"
    ));
    let org = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/issues/issue_key.rs"
    ));
    let policy = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/issue_comment_edit.rs"
    ));
    assert!(admin.contains("admin_edit_comment"));
    assert!(admin.contains("/edit-comment"));
    assert!(!org.contains("admin_edit_comment"));
    assert!(!org.contains("edit-comment"));
    assert!(policy.contains("can_edit_support_comment"));
    assert!(policy.contains("admin_view"));
}

#[test]
fn inv_migration_edited_at() {
    let sql = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/toasty/migrations/0019_issue_comment_edited_at.sql"
    ));
    assert!(sql.contains("edited_at"));
    assert!(sql.contains("issue_comments"));
}
