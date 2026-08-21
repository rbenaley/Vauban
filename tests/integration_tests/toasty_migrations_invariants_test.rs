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
    assert!(
        history.contains("0009_issue_org_key_unique.sql"),
        "history.toml must record 0009_issue_org_key_unique.sql"
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

#[test]
fn inv_real_history_unique_and_sql_files() {
    let history = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/toasty/history.toml"));
    let mut ids = std::collections::HashSet::new();
    let mut names = std::collections::HashSet::new();
    let mut current_id: Option<u64> = None;
    for line in history.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("id = ") {
            let id: u64 = rest.parse().expect("history id");
            assert!(ids.insert(id), "duplicate history id {id}");
            current_id = Some(id);
        }
        if let Some(rest) = line.strip_prefix("name = ") {
            let name = rest.trim_matches('"');
            assert!(
                names.insert(name.to_owned()),
                "duplicate history name {name}"
            );
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("toasty/migrations")
                .join(name);
            assert!(
                path.is_file(),
                "history name {name} (id {:?}) must have SQL on disk",
                current_id
            );
        }
    }
    assert!(!ids.is_empty(), "history.toml must list migrations");
    assert_eq!(ids.len(), names.len());
}

#[test]
fn inv_db_embeds_and_wraps_apply() {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/db.rs"));
    assert!(
        src.contains("embed_migrations!"),
        "src/db.rs must call embed_migrations!"
    );
    assert!(
        src.contains("apply_pending_migrations"),
        "src/db.rs must keep apply_pending_migrations wrapper"
    );
    let forbidden = format!(".{}(", "push_schema");
    assert!(
        !src.contains(&forbidden),
        "src/db.rs must not call push_schema"
    );
}

#[test]
fn inv_embedded_ids_match_history() {
    let set = vcp::db::embedded_migrations();
    let files: Vec<_> = set.migrations().iter().map(|m| m.name()).collect();
    assert!(
        files.contains(&"0000_initial.sql"),
        "embed must include 0000_initial.sql"
    );
    assert!(
        files.contains(&"0019_issue_comment_edited_at.sql"),
        "embed must include latest history SQL"
    );
    let mut ids = std::collections::HashSet::new();
    for m in set.migrations() {
        assert!(ids.insert(m.id()), "duplicate embedded id {}", m.id());
        assert!(!m.sql().is_empty(), "{} SQL must be non-empty", m.name());
    }
}

#[test]
fn inv_cargo_pins_toasty_0_10() {
    let cargo = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"));
    assert!(
        cargo.contains("toasty = { version = \"0.10.0\""),
        "Cargo.toml must pin toasty 0.10.0"
    );
    assert!(
        cargo.contains("toasty-cli = \"0.10.0\""),
        "Cargo.toml must pin toasty-cli 0.10.0"
    );
    assert!(
        cargo.contains("features = [\"postgresql\", \"migration\"]"),
        "toasty must enable postgresql + migration"
    );
}
