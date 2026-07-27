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

[[ -f src/bin/vcp_cli.rs ]] || fail "missing src/bin/vcp_cli.rs (vcp-cli)"

grep -n 'apply_pending_migrations' src/db.rs >/dev/null \
  || fail "src/db.rs must call apply_pending_migrations"

if grep -n '\.push_schema(' src/db.rs >/dev/null; then
  fail "src/db.rs must not call push_schema() (use Toasty migrations)"
fi

if grep -n 'async fn ensure_schema_columns' src/db.rs >/dev/null; then
  fail "scaffold ensure_schema_columns must stay removed"
fi

grep -n 'toasty' Cargo.toml | grep -q 'migration' \
  || fail "Cargo.toml must enable toasty feature migration"

echo "check_toasty_migrations: OK"
