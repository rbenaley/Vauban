//! Source-shape invariants for Toasty migrations.

use std::process::Command;

#[test]
fn inv_check_toasty_migrations_script() {
    let output = Command::new("bash")
        .arg("scripts/check_toasty_migrations.sh")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run check_toasty_migrations.sh");
    assert!(
        output.status.success(),
        "scripts/check_toasty_migrations.sh failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn inv_history_lists_initial_migration() {
    let history = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/toasty/history.toml"));
    assert!(
        history.contains("0000_initial.sql"),
        "history.toml must record 0000_initial.sql"
    );
    assert!(
        history.contains("0007_portal_role_org_check.sql"),
        "history.toml must record 0007_portal_role_org_check.sql"
    );
    assert!(
        history.contains("0008_release_version_sort.sql"),
        "history.toml must record 0008_release_version_sort.sql"
    );
}

#[test]
fn inv_initial_sql_has_core_tables() {
    let sql = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/toasty/migrations/0000_initial.sql"
    ));
    for table in [
        "doc_articles",
        "issues",
        "users",
        "organizations",
        "memberships",
        "releases",
        "auth_sessions",
    ] {
        assert!(
            sql.contains(&format!("CREATE TABLE \"{table}\"")),
            "0000_initial.sql must create {table}"
        );
    }
    assert!(sql.contains("\"body\""), "doc_articles.body required");
    assert!(
        sql.contains("\"updated_at\""),
        "doc_articles.updated_at required"
    );
    assert!(sql.contains("\"details\""), "issues.details required");
}
