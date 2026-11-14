#!/usr/bin/env bash
#
# Test-suite lint: an integration test must not store a fixed asset name.
#
# `idx_assets_name_active` makes the name of a live asset unique. A fixed
# name collides with any row of that name still in the table: one left by
# an earlier run, or by a test that panicked before its final cleanup.
# That made the suite pass once and fail on a rerun.
#
# Four rules:
#   1. The asset fixtures in tests/fixtures/mod.rs never store the
#      caller's name as is. They go through `unique_asset_name`, which
#      appends part of the row UUID.
#   2. A `NewAsset { .. }` literal in a test file never takes a string
#      literal as its name.
#   3. A raw `INSERT INTO assets` in a test file never selects a quoted
#      name with no per-run part (`{..}` placeholder).
#   4. `test_db::cleanup` deletes every asset, with no name filter, so
#      rows do not pile up from one run to the next.
#
# Not covered: names sent through the HTTP API or a form. Two runs in a
# row of the integration suite are the check for those.
#
# Usage: bash vauban-web/scripts/check_test_asset_names_unique.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
TESTS_DIR="${CRATE_DIR}/tests"
FIXTURES="${TESTS_DIR}/fixtures/mod.rs"

status=0

if [[ ! -f "${FIXTURES}" ]]; then
    echo "FAIL: missing fixtures file ${FIXTURES}" >&2
    exit 1
fi

# 1. Fixtures: the helper exists, and no fixture bypasses it.
if ! grep -qE '^pub fn unique_asset_name\(' "${FIXTURES}"; then
    echo "FAIL: tests/fixtures/mod.rs no longer defines unique_asset_name." >&2
    status=1
fi
if grep -nE '^\s*name: name\.to_string\(\),' "${FIXTURES}" >&2; then
    echo "FAIL: a fixture stores the caller's asset name as is." >&2
    echo "      Use unique_asset_name(name, &asset_uuid)." >&2
    status=1
fi

# 2. NewAsset literals in test files: no string literal as the name.
#    The name field sits within the first lines of the literal.
literal_names="$(
    grep -RnE -A4 'NewAsset \{' "${TESTS_DIR}" --include='*.rs' \
        | grep -E '^[^:]+-[0-9]+-\s*name: "' || true
)"
if [[ -n "${literal_names}" ]]; then
    echo "FAIL: a NewAsset literal takes a fixed name:" >&2
    echo "${literal_names}" >&2
    echo "      Use unique_name(\"test-...\")." >&2
    status=1
fi

# 3. Raw SQL inserts: the name expression carries a per-run placeholder.
#    The name is the second selected value, right after the UUID.
raw_fixed="$(
    grep -RnE -A3 'INSERT INTO assets \(' "${TESTS_DIR}" --include='*.rs' \
        | grep -E "gen_random_uuid\(\), '[^'{]*'" || true
)"
if [[ -n "${raw_fixed}" ]]; then
    echo "FAIL: a raw INSERT INTO assets uses a fixed name:" >&2
    echo "${raw_fixed}" >&2
    echo "      Put a per-run tag in the name, for example 'test-x-{stamp}-'." >&2
    status=1
fi

# 4. The cleanup sweeps every asset.
COMMON="${TESTS_DIR}/common/mod.rs"
if ! grep -qE 'sql_query\("DELETE FROM assets"\)' "${COMMON}"; then
    echo "FAIL: test_db::cleanup no longer deletes every asset." >&2
    status=1
fi
if grep -nE 'DELETE FROM assets WHERE' "${COMMON}" >&2; then
    echo "FAIL: test_db::cleanup filters the assets it deletes." >&2
    status=1
fi

if [[ "${status}" -eq 0 ]]; then
    echo "OK: integration tests store no fixed asset name."
fi
exit "${status}"
