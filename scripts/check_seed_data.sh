#!/usr/bin/env bash
# Structural invariants: minimal boot seed vs vcp seed-data CLI.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "check_seed_data: $*" >&2
  exit 1
}

[[ -f src/main.rs ]] || fail "missing src/main.rs"
[[ -f src/cli.rs ]] || fail "missing src/cli.rs"
[[ -f src/db.rs ]] || fail "missing src/db.rs"

grep -n 'seed_minimal_if_empty' src/main.rs >/dev/null \
  || fail "src/main.rs must call seed_minimal_if_empty on server boot"

if grep -n 'ensure_demo_catalog' src/main.rs >/dev/null; then
  fail "src/main.rs must not call ensure_demo_catalog"
fi

# Boot path must not upsert GA releases (only seed-data / seed_demo_catalog).
if grep -n 'upsert_ga_releases' src/main.rs >/dev/null; then
  fail "src/main.rs must not call upsert_ga_releases"
fi

grep -n 'seed_demo_catalog' src/main.rs >/dev/null \
  || fail "src/main.rs must call seed_demo_catalog for seed-data"

grep -n 'fn cli_usage' src/cli.rs >/dev/null \
  || fail "src/cli.rs must define cli_usage"

grep -n 'seed-data' src/cli.rs >/dev/null \
  || fail "src/cli.rs usage must mention seed-data"

grep -n 'fn wants_help' src/cli.rs >/dev/null \
  || fail "src/cli.rs must define wants_help"

grep -n 'pub async fn seed_minimal_if_empty' src/db.rs >/dev/null \
  || fail "src/db.rs must export seed_minimal_if_empty"

grep -n 'pub async fn seed_demo_catalog' src/db.rs >/dev/null \
  || fail "src/db.rs must export seed_demo_catalog"

if grep -n 'pub async fn ensure_demo_catalog' src/db.rs >/dev/null; then
  fail "ensure_demo_catalog must stay removed (use seed_demo_catalog)"
fi

if grep -n 'pub async fn seed_if_empty' src/db.rs >/dev/null; then
  fail "seed_if_empty must stay removed (use seed_minimal_if_empty)"
fi

[[ -f docs/runbooks/seed_data_smoke_test.md ]] \
  || fail "missing docs/runbooks/seed_data_smoke_test.md"

echo "check_seed_data: OK"
