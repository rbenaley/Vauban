#!/usr/bin/env bash
# Structural invariants for Toasty migrations (no push_schema scaffold).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "check_toasty_migrations: $*" >&2
  exit 1
}

[[ -f Toasty.toml ]] || fail "missing Toasty.toml"
[[ -f toasty/history.toml ]] || fail "missing toasty/history.toml"
[[ -d toasty/migrations ]] || fail "missing toasty/migrations/"
[[ -d toasty/snapshots ]] || fail "missing toasty/snapshots/"

sql_count=$(find toasty/migrations -maxdepth 1 -name '*.sql' | wc -l | tr -d ' ')
[[ "$sql_count" -gt 0 ]] || fail "expected at least one .sql under toasty/migrations/"

snap_count=$(find toasty/snapshots -maxdepth 1 -name '*.toml' | wc -l | tr -d ' ')
[[ "$snap_count" -gt 0 ]] || fail "expected at least one snapshot under toasty/snapshots/"

grep -n 'run_migration' src/main.rs >/dev/null \
  || fail "src/main.rs must define run_migration (former vcp-cli)"
grep -nE '"migration"' src/main.rs >/dev/null \
  || fail "src/main.rs must dispatch the migration command"
if [[ -f src/bin/vcp_cli.rs ]]; then
  fail "src/bin/vcp_cli.rs must stay removed (migrations live on vcp)"
fi
if grep -n 'name = "vcp-cli"' Cargo.toml >/dev/null; then
  fail "Cargo.toml must not declare [[bin]] vcp-cli"
fi

grep -n 'apply_pending_migrations' src/db.rs >/dev/null \
  || fail "src/db.rs must call apply_pending_migrations"
grep -n 'embed_migrations!' src/db.rs >/dev/null \
  || fail "src/db.rs must embed migrations via embed_migrations!"

if grep -n '\.push_schema(' src/db.rs >/dev/null; then
  fail "src/db.rs must not call push_schema() (use Toasty migrations)"
fi

if grep -n 'async fn ensure_schema_columns' src/db.rs >/dev/null; then
  fail "scaffold ensure_schema_columns must stay removed"
fi

grep -n 'toasty' Cargo.toml | grep -q 'migration' \
  || fail "Cargo.toml must enable toasty feature migration"

grep -nE 'toasty = \{ version = "0\.10\.0"' Cargo.toml >/dev/null \
  || fail "Cargo.toml must pin toasty = 0.10.0"
grep -nE 'toasty-cli = "0\.10\.0"' Cargo.toml >/dev/null \
  || fail "Cargo.toml must pin toasty-cli = 0.10.0"

echo "check_toasty_migrations: OK"
