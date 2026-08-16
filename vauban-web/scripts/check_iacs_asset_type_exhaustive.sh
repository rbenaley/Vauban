#!/usr/bin/env bash
#
# Lint: every value of the closed `assets.asset_type` vocabulary must
# appear (a) in the SQL CHECK constraint introduced by migration
# 20260817000000_iacs_protocol_profiles and (b) as a Rust variant of the
# `AssetType` enum in `vauban-web/src/models/asset.rs`.
#
# This is a structural lint; the runtime drift between the SQL CHECK
# constraint and the Rust enum is also pinned by the
# `asset_type_check_constraint_matches_rust_enum` integration test
# (see `vauban-web/tests/db/iacs_drift_test.rs`). The lint catches
# regressions BEFORE `cargo test`, which is faster on CI.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
MIGRATION="${REPO_ROOT}/vauban-db/migrations/20260817000000_iacs_protocol_profiles/up.sql"
ENUM_FILE="${REPO_ROOT}/vauban-web/src/models/asset.rs"

if [[ ! -f "${MIGRATION}" ]]; then
    echo "FATAL: migration file missing: ${MIGRATION}" >&2
    exit 1
fi
if [[ ! -f "${ENUM_FILE}" ]]; then
    echo "FATAL: enum file missing: ${ENUM_FILE}" >&2
    exit 1
fi

EXPECTED=(
    "ssh"
    "rdp"
    "iacs_modbus"
    "iacs_opcua"
    "iacs_profinet"
    "iacs_iec104"
    "iacs_enip"
    "iacs_bacnet_sc"
    "iacs_dnp3"
    "iacs_iec61850"
    "iacs_tcp"
)

fail=0

for v in "${EXPECTED[@]}"; do
    if ! grep -qF "'${v}'" "${MIGRATION}"; then
        echo "FAIL: migration is missing string literal '${v}' (assets_asset_type_chk vocabulary)" >&2
        fail=1
    fi
    if ! grep -qE "\"${v}\"" "${ENUM_FILE}"; then
        echo "FAIL: AssetType enum file does not mention canonical wire string \"${v}\"" >&2
        fail=1
    fi
done

# Inverse direction: the CHECK constraint must NOT carry any string
# that the Rust enum does not know about. We extract every
# single-quoted literal from the CHECK clause and confirm membership
# in EXPECTED.
chk_block=$(awk '
    /assets_asset_type_chk CHECK \(asset_type IN/ {capture=1}
    capture {print}
    capture && /\)\)/ {capture=0}
' "${MIGRATION}")

while IFS= read -r literal; do
    [[ -z "${literal}" ]] && continue
    found=0
    for v in "${EXPECTED[@]}"; do
        if [[ "${literal}" == "${v}" ]]; then
            found=1
            break
        fi
    done
    if [[ "${found}" -eq 0 ]]; then
        echo "FAIL: SQL CHECK lists unknown literal '${literal}' (not in EXPECTED)" >&2
        fail=1
    fi
done < <(echo "${chk_block}" | grep -oE "'[a-z_0-9]+'" | tr -d "'")

if [[ "${fail}" -ne 0 ]]; then
    echo
    echo "asset_type vocabulary drift detected -- update either the migration or the Rust enum." >&2
    exit 1
fi

echo "OK -- assets.asset_type vocabulary in lock-step (11 entries)"
