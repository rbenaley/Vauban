//! Embedded, baseline-aware database migration runner.
//!
//! Every directory under `vauban-db/migrations/` is compiled into the
//! binary via [`embed_migrations!`]. The runner applies pending
//! migrations through Diesel's [`MigrationHarness`], which tracks the
//! applied set in the `__diesel_schema_migrations` table (one
//! transaction per migration, loud failure, resumable).
//!
//! # The four schema states
//!
//! Production databases installed before the runner existed were
//! provisioned by applying a consolidated schema file with `psql`, so
//! they carry the full baseline schema but no tracking table. [`run`]
//! therefore classifies the target database before acting:
//!
//! 1. **Nominal** -- `__diesel_schema_migrations` exists: apply the
//!    pending delta, nothing else.
//! 2. **Fresh** -- no tracking table and no schema (probe:
//!    `asset_groups` absent): apply every embedded migration.
//! 3. **Baseline** -- no tracking table but the schema is present and
//!    the baseline sentinels check out: stamp every migration up to
//!    [`BASELINE_VERSION`] as applied (without executing them), then
//!    apply the pending delta.
//! 4. **Unknown / partial** -- schema present but the sentinels fail:
//!    refuse loudly without writing anything. A partial schema must be
//!    repaired by an operator, never paper-covered by the runner.
//!
//! The baseline stamp is only written when the sentinel probes prove
//! that the database matches the frozen baseline schema (the artifacts
//! of the *last* baseline migration plus the seeded virtual asset
//! groups that the services re-verify fail-closed at boot).

use std::fmt;

use diesel::migration::{Migration, MigrationSource};
use diesel::pg::Pg;
use diesel::prelude::*;
use diesel::sql_types::{Bool, Text};
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};

/// Every migration under `vauban-db/migrations/`, compiled in
/// (includes ADR 006 `20260817000000_iacs_protocol_profiles` and
/// `20260817160000_iacs_access_rule_profiles`).
pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

/// Version of the last migration included in the frozen baseline
/// schema (the consolidated schema file applied by legacy installs).
/// Migrations `<= BASELINE_VERSION` are stamped -- not executed -- when
/// the runner adopts a pre-runner database. History up to this version
/// is append-only and frozen (pinned by tests).
pub const BASELINE_VERSION: &str = "20260628000000";

/// Diesel's own DDL for the migration tracking table (kept verbatim so
/// stamped rows are indistinguishable from harness-written rows; the
/// interop is pinned by tests).
const TRACKING_TABLE_DDL: &str = "CREATE TABLE IF NOT EXISTS __diesel_schema_migrations (\
     version VARCHAR(50) PRIMARY KEY NOT NULL,\
     run_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP\
     )";

/// How [`run`] classified the target database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaState {
    /// Tracking table present: normal delta apply.
    Nominal,
    /// Empty database: full apply from zero.
    Fresh,
    /// Pre-runner baseline schema adopted: stamped, then delta apply.
    Baseline,
}

impl fmt::Display for SchemaState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SchemaState::Nominal => write!(f, "nominal"),
            SchemaState::Fresh => write!(f, "fresh"),
            SchemaState::Baseline => write!(f, "baseline"),
        }
    }
}

/// Outcome of a successful [`run`].
#[derive(Debug)]
pub struct MigrateReport {
    /// State detected before any write.
    pub state: SchemaState,
    /// Versions stamped as already-applied (baseline adoption only).
    pub stamped: Vec<String>,
    /// Versions actually executed by the harness, in apply order.
    pub applied: Vec<String>,
}

/// Migration runner error.
#[derive(Debug)]
pub enum MigrateError {
    /// Database query error outside the harness.
    Db(diesel::result::Error),
    /// Harness / migration source error (includes the failing SQL).
    Migration(String),
    /// Schema present but it does not match the frozen baseline:
    /// refusing to stamp or migrate.
    UnknownSchema {
        /// Human-readable list of failed sentinel probes.
        missing: String,
    },
}

impl fmt::Display for MigrateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MigrateError::Db(e) => write!(f, "database error: {e}"),
            MigrateError::Migration(msg) => write!(f, "migration failed: {msg}"),
            MigrateError::UnknownSchema { missing } => write!(
                f,
                "refusing to migrate: the database has a schema but no \
                 __diesel_schema_migrations tracking table, and it does NOT \
                 match the expected baseline (missing: {missing}). This is a \
                 partial or unknown schema; repair it manually before \
                 re-running the migration command. Nothing was modified."
            ),
        }
    }
}

impl std::error::Error for MigrateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            MigrateError::Db(e) => Some(e),
            _ => None,
        }
    }
}

impl From<diesel::result::Error> for MigrateError {
    fn from(e: diesel::result::Error) -> Self {
        MigrateError::Db(e)
    }
}

/// Applies pending embedded migrations, adopting pre-runner baseline
/// databases when the sentinel probes prove it is safe (see the module
/// documentation for the four states).
pub fn run(conn: &mut PgConnection) -> Result<MigrateReport, MigrateError> {
    run_with_source(conn, MIGRATIONS)
}

/// [`run`] with an explicit migration source (tests inject file-based
/// sources with synthetic future migrations).
pub fn run_with_source<S>(conn: &mut PgConnection, source: S) -> Result<MigrateReport, MigrateError>
where
    S: MigrationSource<Pg>,
{
    let state = classify(conn)?;
    let mut stamped = Vec::new();

    if state == SchemaState::Baseline {
        stamped = stamp_baseline(conn, &source)?;
    }

    let applied = conn
        .run_pending_migrations(source)
        .map_err(|e| MigrateError::Migration(e.to_string()))?
        .iter()
        .map(ToString::to_string)
        .collect();

    Ok(MigrateReport {
        state,
        stamped,
        applied,
    })
}

/// Returns the pending migration versions WITHOUT writing anything
/// (unlike the harness, which creates the tracking table as a side
/// effect). Used by `migrate --check` and the supervisor boot check.
pub fn check(conn: &mut PgConnection) -> Result<Vec<String>, MigrateError> {
    check_with_source(conn, MIGRATIONS)
}

/// [`check`] with an explicit migration source.
pub fn check_with_source<S>(conn: &mut PgConnection, source: S) -> Result<Vec<String>, MigrateError>
where
    S: MigrationSource<Pg>,
{
    let all = source_versions(&source)?;
    if !tracking_table_exists(conn)? {
        // No tracking table: on a baseline database every version up to
        // BASELINE_VERSION is de facto applied; on a fresh database
        // everything is pending. Either way nothing is written here.
        if schema_is_empty(conn)? {
            return Ok(all);
        }
        return Ok(all
            .into_iter()
            .filter(|v| v.as_str() > BASELINE_VERSION)
            .collect());
    }
    let applied = applied_versions(conn)?;
    Ok(all.into_iter().filter(|v| !applied.contains(v)).collect())
}

/// Embedded migration versions `<= BASELINE_VERSION`, sorted -- derived
/// from the embedded list, never duplicated by hand.
pub fn baseline_versions() -> Result<Vec<String>, MigrateError> {
    baseline_versions_from(&MIGRATIONS)
}

fn baseline_versions_from<S>(source: &S) -> Result<Vec<String>, MigrateError>
where
    S: MigrationSource<Pg>,
{
    Ok(source_versions(source)?
        .into_iter()
        .filter(|v| v.as_str() <= BASELINE_VERSION)
        .collect())
}

/// All versions of a migration source, sorted ascending.
fn source_versions<S>(source: &S) -> Result<Vec<String>, MigrateError>
where
    S: MigrationSource<Pg>,
{
    let migrations: Vec<Box<dyn Migration<Pg>>> = source
        .migrations()
        .map_err(|e| MigrateError::Migration(e.to_string()))?;
    let mut versions: Vec<String> = migrations
        .iter()
        .map(|m| m.name().version().to_string())
        .collect();
    versions.sort();
    Ok(versions)
}

/// Classifies the database into one of the four states (read-only).
fn classify(conn: &mut PgConnection) -> Result<SchemaState, MigrateError> {
    if tracking_table_exists(conn)? {
        return Ok(SchemaState::Nominal);
    }
    if schema_is_empty(conn)? {
        return Ok(SchemaState::Fresh);
    }
    let missing = failed_baseline_sentinels(conn)?;
    if missing.is_empty() {
        return Ok(SchemaState::Baseline);
    }
    Err(MigrateError::UnknownSchema {
        missing: missing.join(", "),
    })
}

fn tracking_table_exists(conn: &mut PgConnection) -> Result<bool, MigrateError> {
    scalar_bool(
        conn,
        "to_regclass('public.__diesel_schema_migrations') IS NOT NULL",
    )
}

/// A database is considered schema-less when `asset_groups` (created by
/// the very first migration) is absent.
fn schema_is_empty(conn: &mut PgConnection) -> Result<bool, MigrateError> {
    Ok(!scalar_bool(
        conn,
        "to_regclass('public.asset_groups') IS NOT NULL",
    )?)
}

/// Baseline sentinel probes. Returns the list of FAILED probes (empty
/// means the schema matches the frozen baseline):
///
/// - `idx_users_username_lower`: unique index created by the LAST
///   baseline migration (`20260628000000_users_username_case_insensitive`);
///   its presence proves the whole chronological chain ran to the end.
/// - `__all-assets__` / `__all-iacs-assets__` seeds: verified
///   fail-closed at boot by vauban-access and vauban-web; their absence
///   means a partial apply of `20260424` / `20260508`.
fn failed_baseline_sentinels(conn: &mut PgConnection) -> Result<Vec<String>, MigrateError> {
    let mut missing = Vec::new();

    let index_ok = scalar_bool(
        conn,
        "EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = 'public' \
         AND tablename = 'users' AND indexname = 'idx_users_username_lower')",
    )?;
    if !index_ok {
        missing.push("index users.idx_users_username_lower".to_string());
    }

    for slug in ["__all-assets__", "__all-iacs-assets__"] {
        let seed_ok = diesel::select(
            diesel::dsl::sql::<Bool>("EXISTS (SELECT 1 FROM asset_groups WHERE slug = ")
                .bind::<Text, _>(slug)
                .sql(")"),
        )
        .get_result::<bool>(conn)?;
        if !seed_ok {
            missing.push(format!("virtual asset group seed '{slug}'"));
        }
    }

    Ok(missing)
}

/// Stamps every source version `<= BASELINE_VERSION` as applied, in a
/// single transaction, WITHOUT executing any migration SQL. Only called
/// after the sentinel probes proved the schema matches the baseline.
fn stamp_baseline<S>(conn: &mut PgConnection, source: &S) -> Result<Vec<String>, MigrateError>
where
    S: MigrationSource<Pg>,
{
    let versions = baseline_versions_from(source)?;
    conn.transaction::<_, diesel::result::Error, _>(|conn| {
        diesel::sql_query(TRACKING_TABLE_DDL).execute(conn)?;
        for version in &versions {
            diesel::sql_query("INSERT INTO __diesel_schema_migrations (version) VALUES ($1)")
                .bind::<Text, _>(version)
                .execute(conn)?;
        }
        Ok(())
    })?;
    Ok(versions)
}

/// Applied versions read straight from the tracking table (read-only,
/// unlike `MigrationHarness::applied_migrations` which creates the
/// table as a side effect).
fn applied_versions(conn: &mut PgConnection) -> Result<Vec<String>, MigrateError> {
    #[derive(QueryableByName)]
    struct VersionRow {
        #[diesel(sql_type = Text)]
        version: String,
    }

    let rows: Vec<VersionRow> =
        diesel::sql_query("SELECT version FROM __diesel_schema_migrations ORDER BY version")
            .load(conn)?;
    Ok(rows.into_iter().map(|r| r.version).collect())
}

fn scalar_bool(conn: &mut PgConnection, expr: &str) -> Result<bool, MigrateError> {
    Ok(diesel::select(diesel::dsl::sql::<Bool>(expr)).get_result::<bool>(conn)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_version_is_a_14_digit_timestamp() {
        assert_eq!(BASELINE_VERSION.len(), 14);
        assert!(BASELINE_VERSION.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn embedded_versions_are_14_digit_timestamps_so_string_order_is_chronological() {
        let versions = source_versions(&MIGRATIONS).unwrap_or_default();
        assert!(!versions.is_empty());
        for v in &versions {
            assert_eq!(v.len(), 14, "non-canonical migration version: {v}");
            assert!(
                v.chars().all(|c| c.is_ascii_digit()),
                "non-numeric migration version: {v}"
            );
        }
    }

    #[test]
    fn schema_state_display_is_stable() {
        assert_eq!(SchemaState::Nominal.to_string(), "nominal");
        assert_eq!(SchemaState::Fresh.to_string(), "fresh");
        assert_eq!(SchemaState::Baseline.to_string(), "baseline");
    }

    #[test]
    fn unknown_schema_error_message_names_the_missing_sentinels() {
        let err = MigrateError::UnknownSchema {
            missing: "index users.idx_users_username_lower".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("refusing to migrate"));
        assert!(msg.contains("idx_users_username_lower"));
        assert!(msg.contains("Nothing was modified"));
    }
}
