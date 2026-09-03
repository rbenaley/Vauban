//! Source-grep pin tests for the embedded database migration runner
//! wiring: the FreeBSD package scripts and the supervisor boot check.
//!
//! Background (2026-07-02 incident): a from-scratch FreeBSD install
//! ended up with a PARTIAL schema because +POST_INSTALL applied each
//! migration with `psql -q ... 2>/dev/null` (no ON_ERROR_STOP, no exit
//! code) and +MANIFEST did not declare postgresql18-contrib (so
//! `uuid_generate_v4()` did not exist and every CREATE TABLE cascaded
//! into failure -- silently). These pins make each ingredient of that
//! incident a CI failure:
//!
//! - INV-PKG-1: +MANIFEST declares the postgresql18-contrib dependency.
//! - INV-PKG-2: +POST_INSTALL delegates schema work to
//!   `vauban-supervisor migrate` in BOTH branches (fresh and upgrade)
//!   and never applies migration SQL through psql again.
//! - INV-PKG-3: +POST_INSTALL fails loudly (DB_SETUP_FAILED + exit 1)
//!   and carries no misleading recovery instructions.
//! - INV-PKG-4: +PRE_INSTALL stops a running service before an upgrade
//!   (no schema-N+1 / code-N window while migrate runs).
//! - INV-PKG-5: every pkg shell script parses (`sh -n`).
//! - INV-BOOT: the supervisor refuses to boot on pending migrations
//!   (fail-closed) but only warns when the database is unreachable,
//!   and never auto-migrates at boot.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::Command;

const MANIFEST: &str = include_str!("../../pkg/+MANIFEST");
const PRE_INSTALL: &str = include_str!("../../pkg/+PRE_INSTALL");
const POST_INSTALL: &str = include_str!("../../pkg/+POST_INSTALL");
const BUILD_PKG: &str = include_str!("../../pkg/build-pkg.sh");
const SUPERVISOR_MAIN: &str = include_str!("../src/main.rs");
const ADMIN: &str = include_str!("../src/admin.rs");

// ==================== INV-PKG-1: contrib dependency ====================

#[test]
fn manifest_declares_postgresql_contrib_dependency() {
    assert!(
        MANIFEST.contains("postgresql18-contrib"),
        "+MANIFEST MUST depend on postgresql18-contrib: the initial schema \
         creates the uuid-ossp/pgcrypto extensions, which live in the \
         contrib package (INV-PKG-1, root cause of the 2026-07-02 incident)."
    );
    assert!(
        MANIFEST.contains("databases/postgresql18-contrib"),
        "+MANIFEST MUST reference the databases/postgresql18-contrib origin."
    );
}

// ============ INV-PKG-2: runner in both branches, no psql apply ============

#[test]
fn post_install_runs_the_embedded_migrate_command_in_both_branches() {
    let occurrences = POST_INSTALL.matches("${MIGRATE_CMD}").count();
    assert!(
        POST_INSTALL.contains("libexec/vauban/vauban-supervisor")
            && POST_INSTALL.contains("migrate --database-url postgresql:///vauban"),
        "+POST_INSTALL MUST define the embedded migrate command, connecting \
         as the postgres OS user over the local socket (INV-PKG-2)."
    );
    assert!(
        occurrences >= 4,
        "+POST_INSTALL MUST invoke/reference ${{MIGRATE_CMD}} in the fresh \
         branch, the upgrade branch, and the recovery instructions; found \
         only {occurrences} occurrences (INV-PKG-2)."
    );
}

#[test]
fn post_install_never_applies_migration_sql_via_psql() {
    assert!(
        !POST_INSTALL.contains("up.sql"),
        "+POST_INSTALL MUST NOT apply migration SQL files with psql; all \
         schema work goes through `vauban-supervisor migrate` (INV-PKG-2)."
    );
    assert!(
        !POST_INSTALL.contains("vauban-schema.sql"),
        "+POST_INSTALL MUST NOT reference a consolidated schema file; the \
         embedded runner owns fresh installs too (INV-PKG-2)."
    );
    for line in POST_INSTALL.lines() {
        if line.contains("psql") && line.contains("-f ") {
            panic!(
                "+POST_INSTALL applies a SQL file via psql -f; migrations \
                 must go through the embedded runner (INV-PKG-2): {line}"
            );
        }
    }
}

#[test]
fn post_install_migrate_invocations_are_not_silenced() {
    for line in POST_INSTALL.lines() {
        if line.contains("MIGRATE_CMD") {
            assert!(
                !line.contains("2>/dev/null") && !line.contains("|| true"),
                "+POST_INSTALL MUST NOT silence the migrate command \
                 (INV-PKG-2/3): {line}"
            );
        }
    }
}

// ==================== INV-PKG-3: loud failure ====================

#[test]
fn post_install_fails_loudly_on_migration_failure() {
    assert!(
        POST_INSTALL.contains("DB_SETUP_FAILED=1"),
        "+POST_INSTALL MUST flag database setup failures (INV-PKG-3)."
    );
    assert!(
        POST_INSTALL.contains("exit 1"),
        "+POST_INSTALL MUST exit non-zero when the schema was not applied, \
         so pkg(8) reports a POST-INSTALL failure (INV-PKG-3)."
    );
    let flag_check = POST_INSTALL
        .rfind("DB_SETUP_FAILED}\" = \"1\"")
        .expect("+POST_INSTALL must gate its final exit on DB_SETUP_FAILED");
    let exit = POST_INSTALL
        .rfind("exit 1")
        .expect("exit 1 present (asserted above)");
    assert!(
        exit > flag_check,
        "the final exit 1 MUST come after (inside) the DB_SETUP_FAILED gate \
         at the very end of the script (INV-PKG-3)."
    );
}

#[test]
fn post_install_has_no_misleading_rerun_instruction() {
    assert!(
        !POST_INSTALL.contains("pkg info -D"),
        "+POST_INSTALL MUST NOT tell operators that `pkg info -D` re-runs \
         the post-install (it only prints the install message); the correct \
         recovery is `su -m postgres -c \"... migrate ...\"` (INV-PKG-3)."
    );
}

// ==================== INV-PKG-4: stop service before upgrade ====================

#[test]
fn pre_install_stops_a_running_service_before_upgrade() {
    assert!(
        PRE_INSTALL.contains("service vauban onestatus")
            && PRE_INSTALL.contains("service vauban onestop"),
        "+PRE_INSTALL MUST stop a running Vauban service before the new \
         files land, so migrations never run under old binaries (INV-PKG-4)."
    );
}

// ==================== INV-PKG-5: scripts parse ====================

#[test]
fn every_pkg_shell_script_parses() {
    for script in [
        "+PRE_INSTALL",
        "+POST_INSTALL",
        "+PRE_DEINSTALL",
        "+POST_DEINSTALL",
        "build-pkg.sh",
        "privsep_fs_apply.sh",
    ] {
        let path = format!("{}/../pkg/{script}", env!("CARGO_MANIFEST_DIR"));
        let status = Command::new("sh")
            .arg("-n")
            .arg(&path)
            .status()
            .expect("run sh -n");
        assert!(status.success(), "sh -n failed on pkg/{script} (INV-PKG-5)");
    }
}

#[test]
fn build_pkg_does_not_generate_a_consolidated_schema() {
    assert!(
        !BUILD_PKG.contains("vauban-schema.sql"),
        "build-pkg.sh MUST NOT generate a consolidated schema file; the \
         embedded runner is the single source of schema truth (INV-PKG-2)."
    );
}

// ==================== INV-BOOT: supervisor boot check ====================

fn fn_body<'a>(src: &'a str, signature: &str) -> &'a str {
    let start = src
        .find(signature)
        .unwrap_or_else(|| panic!("`{signature}` must exist in source"));
    let rest = &src[start..];
    let end = rest[1..].find("\nfn ").map(|i| i + 1).unwrap_or(rest.len());
    &rest[..end]
}

#[test]
fn supervisor_boot_checks_schema_before_spawning_services() {
    let body = fn_body(SUPERVISOR_MAIN, "fn run_supervisor(");
    let check = body
        .find("check_schema_up_to_date(")
        .expect("run_supervisor MUST call check_schema_up_to_date (INV-BOOT)");
    let spawn = body
        .find("PipeStore::new(")
        .expect("run_supervisor creates the IPC topology");
    assert!(
        check < spawn,
        "the schema check MUST run before any service plumbing is created \
         (INV-BOOT)."
    );
}

#[test]
fn boot_check_fails_closed_on_pending_and_warns_on_unreachable() {
    let body = fn_body(SUPERVISOR_MAIN, "fn check_schema_up_to_date(");
    assert!(
        body.contains("vauban_db::migrations::check("),
        "the boot check MUST use the read-only `check` entry point (INV-BOOT)."
    );
    assert!(
        !body.contains("migrations::run("),
        "the boot check MUST NEVER auto-migrate at boot (INV-BOOT)."
    );
    assert!(
        body.contains("warn!") && body.contains("return Ok(())"),
        "an unreachable database MUST only warn and continue (INV-BOOT)."
    );
    assert!(
        body.contains("bail!"),
        "pending migrations MUST abort the boot (fail-closed, INV-BOOT)."
    );
}

#[test]
fn migrate_subcommand_resolves_url_without_config_when_flagged() {
    let body = fn_body(ADMIN, "fn resolve_migrate_database_url(");
    let flag = body
        .find("if let Some(url) = flag")
        .expect("--database-url flag must be checked first");
    let env = body
        .find("DATABASE_URL")
        .expect("DATABASE_URL env fallback must exist");
    let config = body
        .find("SupervisorConfig::load_auto()")
        .expect("config fallback must exist");
    assert!(
        flag < env && env < config,
        "URL resolution order MUST be flag > env > config: the post-install \
         runs as the postgres OS user, which cannot read vauban.conf."
    );
}
