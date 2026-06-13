#!/usr/bin/env bash
#
# VAU-007 / INV-4 lint: the API key lookup (ApiKey::hash_key /
# api_keys.key_hash) must live ONLY in the single seam
# `src/middleware/api_key.rs`. No `/api/v1/*` handler may re-implement
# credential parsing/lookup. Mirrors
# `tests/security/api_key_invariants_test.rs::inv4_*` so the regression is
# caught before `cargo test`.
#
# Usage: bash vauban-web/scripts/check_api_key_single_seam.sh
set -euo pipefail

# Resolve the vauban-web crate root from this script's location.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
HANDLERS_DIR="${CRATE_DIR}/src/handlers/api"
SEAM="${CRATE_DIR}/src/middleware/api_key.rs"

status=0

if [[ ! -f "${SEAM}" ]]; then
    echo "FAIL: missing API key seam ${SEAM}" >&2
    exit 1
fi

# 1. No handler under /api/v1/* may resolve the key.
if grep -RInE 'hash_key|key_hash' "${HANDLERS_DIR}" >/dev/null 2>&1; then
    echo "FAIL (INV-4): an /api/v1 handler references the API key lookup." >&2
    echo "             The only seam is src/middleware/api_key.rs." >&2
    grep -RInE 'hash_key|key_hash' "${HANDLERS_DIR}" >&2 || true
    status=1
fi

# 2. The seam itself must perform the hash + lookup.
if ! grep -qE 'ApiKey::hash_key' "${SEAM}"; then
    echo "FAIL (INV-4): the seam does not hash the raw key." >&2
    status=1
fi
if ! grep -qE 'key_hash\.eq' "${SEAM}"; then
    echo "FAIL (INV-4): the seam does not look up api_keys.key_hash." >&2
    status=1
fi

if [[ "${status}" -eq 0 ]]; then
    echo "OK: API key resolution is confined to the single seam (INV-4)."
fi

exit "${status}"
