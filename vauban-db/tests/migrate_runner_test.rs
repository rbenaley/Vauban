//! Battle tests for the embedded, baseline-aware migration runner
//! (`vauban_db::migrations`).
//!
//! Every DB test provisions a throwaway PostgreSQL database through the
//! maintenance URL (`VAUBAN_TEST_MAINTENANCE_URL`, default
//! `postgresql://localhost/postgres`; the role needs CREATEDB, same
//! prerequisite as `vauban-web/scripts/setup_test_db.sh`), so nothing
//! here touches the shared `vauban_test` catalog.
//!
//! Invariants pinned:
//!
//! - INV-FRESH: an empty database gets the FULL embedded chain and a
//!   complete tracking table; a second run is a strict no-op.
//! - INV-BASELINE: a pre-runner database (schema applied by the
//!   consolidated `vauban_schema.sql`, no tracking table) is adopted by
//!   stamping -- never re-executing -- the baseline versions.
//! - INV-EQUIV: the fresh path and the adopted-baseline path converge
//!   to byte-identical schemas (catalog snapshot).
//! - INV-DELTA: after adoption, only post-baseline migrations run.
//! - INV-REFUSE: a partial/unknown schema (the 2026-07-02 incident
//!   shape) is refused loudly with ZERO writes.
//! - INV-INTEROP: stamped rows are indistinguishable from rows written
//!   by Diesel's own harness (same table, same semantics).
//! - INV-FROZEN: the committed fixture is exactly the concatenation of
//!   the baseline migrations -- editing a historical `up.sql` fails CI.

// The whole suite requires the `migrations` feature (enabled by
// feature unification whenever vauban-supervisor is part of the build,
// i.e. any workspace-wide cargo invocation).
#![cfg(feature = "migrations")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use diesel::connection::SimpleConnection;
use diesel::prelude::*;
use diesel::sql_types::Text;
use diesel_migrations::{FileBasedMigrations, MigrationHarness};
use vauban_db::migrations::{
    BASELINE_VERSION, MIGRATIONS, MigrateError, SchemaState, baseline_versions, check,
    check_with_source, run, run_with_source,
};

/// Consolidated baseline schema exactly as applied on client machines.
const BASELINE_FIXTURE: &str = include_str!("fixtures/vauban_schema.sql");

/// The frozen baseline history. Duplicated here ON PURPOSE (and only
/// here): the runner derives its list from the embedded migrations, so
/// this literal list pins renames/insertions/deletions of any
/// pre-baseline migration.
const EXPECTED_BASELINE_VERSIONS: [&str; 24] = [
    "20260102000000",
    "20260110000000",
    "20260311000000",
    "20260312000000",
    "20260326000000",
    "20260328000000",
    "20260329000000",
    "20260330000000",
    "20260412000000",
    "20260418000000",
    "20260419000000",
    "20260420000000",
    "20260424000000",
    "20260425000000",
    "20260430000000",
    "20260501000000",
    "20260506000000",
    "20260508000000",
    "20260509000000",
    "20260510000000",
    "20260513000000",
    "20260614000000",
    "20260625000000",
    "20260628000000",
];

// ==================== scratch database plumbing ====================

static SCRATCH_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn maintenance_url() -> String {
    std::env::var("VAUBAN_TEST_MAINTENANCE_URL")
        .unwrap_or_else(|_| "postgresql://localhost/postgres".to_string())
}

/// Replace the database path segment of the maintenance URL.
fn url_for_db(name: &str) -> String {
    let base = maintenance_url();
    let (before_query, query) = match base.split_once('?') {
        Some((b, q)) => (b.to_string(), Some(q.to_string())),
        None => (base, None),
    };
    let scheme_end = before_query
        .find("://")
        .expect("maintenance URL must carry a scheme")
        + 3;
    let (scheme, rest) = before_query.split_at(scheme_end);
    let authority = match rest.rfind('/') {
        Some(i) => &rest[..i],
        None => rest,
    };
    let mut url = format!("{scheme}{authority}/{name}");
    if let Some(q) = query {
        url.push('?');
        url.push_str(&q);
    }
    url
}

/// Throwaway database dropped (WITH FORCE) on scope exit, panic included.
struct ScratchDb {
    name: String,
}

impl ScratchDb {
    fn create(hint: &str) -> Self {
        let name = format!(
            "vauban_migr_{hint}_{}_{}",
            std::process::id(),
            SCRATCH_COUNTER.fetch_add(1, Ordering::SeqCst)
        );
        let mut conn = PgConnection::establish(&maintenance_url()).unwrap_or_else(|e| {
            panic!(
                "cannot connect to maintenance database ({}): {e}; \
                 set VAUBAN_TEST_MAINTENANCE_URL",
                maintenance_url()
            )
        });
        diesel::sql_query(format!(r#"CREATE DATABASE "{name}""#))
            .execute(&mut conn)
            .expect("CREATE DATABASE failed");
        Self { name }
    }

    fn connect(&self) -> PgConnection {
        PgConnection::establish(&url_for_db(&self.name)).expect("connect to scratch DB")
    }
}

impl Drop for ScratchDb {
    fn drop(&mut self) {
        if let Ok(mut conn) = PgConnection::establish(&maintenance_url()) {
            let _ = diesel::sql_query(format!(
                r#"DROP DATABASE IF EXISTS "{}" WITH (FORCE)"#,
                self.name
            ))
            .execute(&mut conn);
        }
    }
}

// ==================== helpers ====================

#[derive(QueryableByName)]
struct TextRow {
    #[diesel(sql_type = Text)]
    item: String,
}

fn text_rows(conn: &mut PgConnection, query: &str) -> Vec<String> {
    diesel::sql_query(query)
        .load::<TextRow>(conn)
        .expect("catalog query failed")
        .into_iter()
        .map(|r| r.item)
        .collect()
}

fn tracking_table_exists(conn: &mut PgConnection) -> bool {
    text_rows(
        conn,
        "SELECT coalesce(to_regclass('public.__diesel_schema_migrations')::text, '') AS item",
    )
    .first()
    .map(|s| !s.is_empty())
    .unwrap_or(false)
}

fn tracked_versions(conn: &mut PgConnection) -> Vec<String> {
    text_rows(
        conn,
        "SELECT version AS item FROM __diesel_schema_migrations ORDER BY version",
    )
}

fn embedded_versions() -> Vec<String> {
    use diesel::migration::{Migration, MigrationSource};
    let migrations: Vec<Box<dyn Migration<diesel::pg::Pg>>> =
        MigrationSource::<diesel::pg::Pg>::migrations(&MIGRATIONS).expect("embedded migrations");
    let mut versions: Vec<String> = migrations
        .iter()
        .map(|m| m.name().version().to_string())
        .collect();
    versions.sort();
    versions
}

/// Deterministic, order-independent snapshot of everything the
/// migrations can shape: tables/columns, indexes, constraints,
/// triggers, functions, sequences, extensions, plus the seeded virtual
/// asset groups. Two databases with equal snapshots are equivalent for
/// the application.
fn schema_snapshot(conn: &mut PgConnection) -> Vec<String> {
    let mut snapshot = Vec::new();
    snapshot.extend(text_rows(
        conn,
        "SELECT 'column:' || table_name || ':' || column_name || ':' || data_type \
         || ':' || coalesce(column_default, '<none>') || ':' || is_nullable \
         || ':' || coalesce(character_maximum_length::text, '-') AS item \
         FROM information_schema.columns WHERE table_schema = 'public' ORDER BY 1",
    ));
    snapshot.extend(text_rows(
        conn,
        "SELECT 'index:' || tablename || ':' || indexname || ':' || indexdef AS item \
         FROM pg_indexes WHERE schemaname = 'public' ORDER BY 1",
    ));
    snapshot.extend(text_rows(
        conn,
        "SELECT 'constraint:' || conrelid::regclass::text || ':' || conname || ':' \
         || pg_get_constraintdef(oid) AS item \
         FROM pg_constraint WHERE connamespace = 'public'::regnamespace ORDER BY 1",
    ));
    snapshot.extend(text_rows(
        conn,
        "SELECT 'trigger:' || tgrelid::regclass::text || ':' || tgname || ':' \
         || pg_get_triggerdef(oid) AS item \
         FROM pg_trigger WHERE NOT tgisinternal ORDER BY 1",
    ));
    snapshot.extend(text_rows(
        conn,
        "SELECT 'function:' || p.proname || ':' || pg_get_functiondef(p.oid) AS item \
         FROM pg_proc p JOIN pg_namespace n ON p.pronamespace = n.oid \
         WHERE n.nspname = 'public' AND p.prokind = 'f' ORDER BY 1",
    ));
    snapshot.extend(text_rows(
        conn,
        "SELECT 'sequence:' || sequence_name AS item \
         FROM information_schema.sequences WHERE sequence_schema = 'public' ORDER BY 1",
    ));
    snapshot.extend(text_rows(
        conn,
        "SELECT 'extension:' || extname AS item FROM pg_extension ORDER BY 1",
    ));
    snapshot.extend(text_rows(
        conn,
        "SELECT 'seed:' || slug AS item FROM asset_groups ORDER BY 1",
    ));
    snapshot
}

fn apply_baseline_fixture(conn: &mut PgConnection) {
    conn.batch_execute(BASELINE_FIXTURE)
        .expect("baseline fixture must apply cleanly on an empty database");
}

fn migrations_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations")
}

// ==================== INV-FRESH ====================

#[test]
fn fresh_database_gets_the_full_chain_and_reruns_are_noops() {
    let db = ScratchDb::create("fresh");
    let mut conn = db.connect();

    let report = run(&mut conn).expect("fresh run must succeed");
    assert_eq!(report.state, SchemaState::Fresh);
    assert!(report.stamped.is_empty(), "fresh install never stamps");
    assert_eq!(
        report.applied,
        embedded_versions(),
        "fresh install must apply every embedded migration in order"
    );

    assert_eq!(
        tracked_versions(&mut conn),
        embedded_versions(),
        "tracking table must record the full chain"
    );

    let rerun = run(&mut conn).expect("rerun must succeed");
    assert_eq!(rerun.state, SchemaState::Nominal);
    assert!(rerun.stamped.is_empty());
    assert!(rerun.applied.is_empty(), "second run must be a no-op");

    assert!(
        check(&mut conn).expect("check").is_empty(),
        "check must report nothing pending after a full apply"
    );
}

// ==================== INV-BASELINE ====================

#[test]
fn baseline_database_is_adopted_by_stamping_not_reexecuting() {
    let db = ScratchDb::create("baseline");
    let mut conn = db.connect();
    apply_baseline_fixture(&mut conn);
    assert!(
        !tracking_table_exists(&mut conn),
        "fixture must not carry a tracking table (pre-runner install)"
    );

    let report = run(&mut conn).expect("baseline adoption must succeed");
    assert_eq!(report.state, SchemaState::Baseline);
    assert_eq!(
        report.stamped,
        EXPECTED_BASELINE_VERSIONS
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        "adoption must stamp exactly the frozen baseline versions"
    );
    for version in &report.applied {
        assert!(
            version.as_str() > BASELINE_VERSION,
            "adoption must never re-execute a baseline migration (got {version})"
        );
    }

    assert!(check(&mut conn).expect("check").is_empty());

    let rerun = run(&mut conn).expect("rerun");
    assert_eq!(rerun.state, SchemaState::Nominal);
    assert!(rerun.applied.is_empty());
}

// ==================== INV-EQUIV ====================

#[test]
fn fresh_path_and_baseline_path_converge_to_identical_schemas() {
    let fresh_db = ScratchDb::create("equiv_fresh");
    let mut fresh_conn = fresh_db.connect();
    run(&mut fresh_conn).expect("fresh run");

    let legacy_db = ScratchDb::create("equiv_legacy");
    let mut legacy_conn = legacy_db.connect();
    apply_baseline_fixture(&mut legacy_conn);
    run(&mut legacy_conn).expect("baseline adoption run");

    let fresh_snapshot = schema_snapshot(&mut fresh_conn);
    let legacy_snapshot = schema_snapshot(&mut legacy_conn);
    assert!(
        !fresh_snapshot.is_empty(),
        "snapshot must not be trivially empty"
    );
    assert_eq!(
        fresh_snapshot, legacy_snapshot,
        "fresh-install and adopted-baseline databases must be schema-identical"
    );
}

// ==================== INV-DELTA ====================

#[test]
fn post_baseline_delta_applies_only_new_migrations_on_adopted_databases() {
    // Clone the real migration tree and append a synthetic future
    // migration, proving the upgrade path (version N+1) end to end.
    let tmp = tempfile::tempdir().expect("tempdir");
    let synthetic_version = "20991231000000";
    copy_migrations_tree(&migrations_dir(), tmp.path());
    let synthetic = tmp
        .path()
        .join(format!("{synthetic_version}_synthetic_delta"));
    std::fs::create_dir(&synthetic).expect("mkdir synthetic migration");
    std::fs::write(
        synthetic.join("up.sql"),
        "CREATE TABLE synthetic_delta_probe (id INTEGER PRIMARY KEY);\n",
    )
    .expect("write up.sql");
    std::fs::write(
        synthetic.join("down.sql"),
        "DROP TABLE synthetic_delta_probe;\n",
    )
    .expect("write down.sql");
    let source = FileBasedMigrations::from_path(tmp.path()).expect("file-based source");

    // Every REAL post-baseline migration in the tree is pending on an
    // adopted-baseline database too, in version order, with the
    // synthetic future migration last.
    let mut expected_deltas: Vec<String> = std::fs::read_dir(migrations_dir())
        .expect("read migrations dir")
        .filter_map(|entry| {
            let name = entry.expect("dir entry").file_name();
            let name = name.to_string_lossy();
            let version = name.split('_').next().unwrap_or("").to_string();
            (version.as_str() > BASELINE_VERSION).then_some(version)
        })
        .collect();
    expected_deltas.sort();
    expected_deltas.push(synthetic_version.to_string());

    let db = ScratchDb::create("delta");
    let mut conn = db.connect();
    apply_baseline_fixture(&mut conn);

    // Read-only check must see exactly the post-baseline deltas as pending.
    let pending = check_with_source(&mut conn, source.clone()).expect("check");
    assert_eq!(pending, expected_deltas);
    assert!(
        !tracking_table_exists(&mut conn),
        "check must not create the tracking table"
    );

    let report = run_with_source(&mut conn, source).expect("delta run");
    assert_eq!(report.state, SchemaState::Baseline);
    assert_eq!(report.stamped.len(), EXPECTED_BASELINE_VERSIONS.len());
    assert_eq!(
        report.applied, expected_deltas,
        "only the post-baseline migrations must be executed"
    );

    let probe = text_rows(
        &mut conn,
        "SELECT coalesce(to_regclass('public.synthetic_delta_probe')::text, '') AS item",
    );
    assert_eq!(probe, vec!["synthetic_delta_probe".to_string()]);
}

fn copy_migrations_tree(from: &Path, to: &Path) {
    for entry in std::fs::read_dir(from).expect("read migrations dir") {
        let entry = entry.expect("dir entry");
        if !entry.path().is_dir() {
            continue;
        }
        let dest = to.join(entry.file_name());
        std::fs::create_dir(&dest).expect("mkdir migration copy");
        for file in std::fs::read_dir(entry.path()).expect("read migration dir") {
            let file = file.expect("file entry");
            if file.path().is_file() {
                std::fs::copy(file.path(), dest.join(file.file_name())).expect("copy sql");
            }
        }
    }
}

// ==================== INV-REFUSE ====================

/// Fixture truncated right before the last baseline migration: the
/// sentinel index is missing, exactly like a partial apply.
fn truncated_fixture() -> String {
    let last_banner = format!("-- Migration: {BASELINE_VERSION}");
    let idx = BASELINE_FIXTURE
        .find(&last_banner)
        .expect("fixture must contain the last baseline migration banner");
    let cut = BASELINE_FIXTURE[..idx]
        .rfind("-- ====")
        .expect("banner separator before the last migration");
    BASELINE_FIXTURE[..cut].to_string()
}

#[test]
fn partial_schema_is_refused_without_any_write() {
    let db = ScratchDb::create("partial");
    let mut conn = db.connect();
    conn.batch_execute(&truncated_fixture())
        .expect("truncated fixture applies (it is a valid prefix)");

    let err = run(&mut conn).expect_err("partial schema must be refused");
    match &err {
        MigrateError::UnknownSchema { missing } => {
            assert!(
                missing.contains("idx_users_username_lower"),
                "diagnostic must name the failed sentinel, got: {missing}"
            );
        }
        other => panic!("expected UnknownSchema, got: {other}"),
    }
    assert!(
        !tracking_table_exists(&mut conn),
        "a refused adoption must not create the tracking table (zero writes)"
    );
}

#[test]
fn missing_virtual_group_seed_is_refused_without_any_write() {
    let db = ScratchDb::create("noseed");
    let mut conn = db.connect();
    apply_baseline_fixture(&mut conn);
    // The baseline schema itself fences virtual-group deletion with a
    // trigger; bypass it to forge the corrupted legacy state under test.
    conn.batch_execute(
        "ALTER TABLE asset_groups DISABLE TRIGGER USER;\
         DELETE FROM asset_groups WHERE slug = '__all-assets__';\
         ALTER TABLE asset_groups ENABLE TRIGGER USER;",
    )
    .expect("forge a legacy database with a missing seed");

    let err = run(&mut conn).expect_err("missing seed must be refused");
    match &err {
        MigrateError::UnknownSchema { missing } => {
            assert!(
                missing.contains("__all-assets__"),
                "diagnostic must name the missing seed, got: {missing}"
            );
        }
        other => panic!("expected UnknownSchema, got: {other}"),
    }
    assert!(!tracking_table_exists(&mut conn));
}

// ==================== INV-INTEROP ====================

#[test]
fn stamped_rows_are_recognized_by_diesel_harness() {
    let db = ScratchDb::create("interop");
    let mut conn = db.connect();
    apply_baseline_fixture(&mut conn);
    run(&mut conn).expect("adoption");

    let applied = MigrationHarness::<diesel::pg::Pg>::applied_migrations(&mut conn)
        .expect("harness applied_migrations");
    let applied: Vec<String> = applied.iter().map(ToString::to_string).collect();
    for version in EXPECTED_BASELINE_VERSIONS {
        assert!(
            applied.iter().any(|v| v == version),
            "diesel harness must consider stamped version {version} applied"
        );
    }
}

// ==================== INV-FROZEN / pins ====================

#[test]
fn baseline_versions_match_the_frozen_history() {
    let versions = baseline_versions().expect("baseline_versions");
    assert_eq!(
        versions,
        EXPECTED_BASELINE_VERSIONS
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        "the baseline history is frozen: renaming, inserting or deleting a \
         pre-baseline migration breaks every deployed installation"
    );
}

#[test]
fn fixture_matches_frozen_migration_history() {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(migrations_dir())
        .expect("read migrations dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();

    let mut regenerated = String::new();
    for dir in dirs {
        let name = dir
            .file_name()
            .and_then(|n| n.to_str())
            .expect("migration dir name")
            .to_string();
        let version = name.split('_').next().unwrap_or_default();
        if version > BASELINE_VERSION {
            continue;
        }
        let up = std::fs::read_to_string(dir.join("up.sql")).expect("read up.sql");
        regenerated.push_str("-- =============================================================\n");
        regenerated.push_str(&format!("-- Migration: {name}\n"));
        regenerated.push_str("-- =============================================================\n");
        regenerated.push_str(&up);
        regenerated.push('\n');
    }

    assert_eq!(
        BASELINE_FIXTURE, regenerated,
        "tests/fixtures/vauban_schema.sql must be the exact concatenation of \
         the frozen baseline migrations; historical up.sql files are append-only"
    );
}

#[test]
fn migrations_are_transaction_safe() {
    for entry in std::fs::read_dir(migrations_dir()).expect("read migrations dir") {
        let entry = entry.expect("dir entry");
        if !entry.path().is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        let up = std::fs::read_to_string(entry.path().join("up.sql")).expect("read up.sql");
        assert!(
            !up.to_uppercase().contains("CONCURRENTLY"),
            "{name}/up.sql uses CONCURRENTLY, which cannot run inside the \
             per-migration transaction the runner relies on"
        );
        let metadata = entry.path().join("metadata.toml");
        if metadata.exists() {
            let content = std::fs::read_to_string(&metadata).expect("read metadata.toml");
            assert!(
                !content.contains("run_in_transaction"),
                "{name}/metadata.toml overrides run_in_transaction; the runner \
                 requires per-migration transactions"
            );
        }
    }
}
