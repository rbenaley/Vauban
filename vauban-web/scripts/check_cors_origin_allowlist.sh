#!/usr/bin/env bash
#
# VAU-010 lint: the CORS origin decision must be driven EXCLUSIVELY by the
# fixed `server.public_origins` allowlist, never by the client-controlled
# `Host` header. Mirrors the in-crate pin test
# `src/main.rs::tests::cors_seam_is_pinned_to_config_allowlist` so the
# regression is caught before `cargo test`.
#
# Usage: bash vauban-web/scripts/check_cors_origin_allowlist.sh
#
# NOTE: never pipe into `grep -q` here. Under `set -o pipefail`,
# `grep -q` exits on the first match and closes the pipe; the upstream
# `printf` then dies with SIGPIPE (141) and the pipeline status flips
# to non-zero INTERMITTENTLY. `grep ... >/dev/null` drains its whole
# input and is immune.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
MAIN="${CRATE_DIR}/src/main.rs"
CONFIG="${CRATE_DIR}/src/config.rs"

status=0

if [[ ! -f "${MAIN}" || ! -f "${CONFIG}" ]]; then
    echo "FAIL: missing ${MAIN} or ${CONFIG}" >&2
    exit 1
fi

# Production portion of main.rs only (everything before the test module), so
# the CORS E2E test helper -- which deliberately sends a Host header to prove
# it is ignored -- does not trip the drift guards below.
PROD_MAIN="$(awk '/^#\[cfg\(test\)\]/{exit} {print}' "${MAIN}")"

# INV-1: the Host-based predicate must be gone for good.
if printf '%s' "${PROD_MAIN}" | grep -E 'fn is_same_origin' >/dev/null; then
    echo "FAIL (VAU-010 INV-1): is_same_origin (Host-based CORS) reappeared in main.rs." >&2
    status=1
fi
# AllowOrigin::predicate is the only tower-http API exposing the request parts
# (hence Host). It must not be used for the CORS origin decision.
if printf '%s' "${PROD_MAIN}" | grep -E 'AllowOrigin::predicate' >/dev/null; then
    echo "FAIL (VAU-010 INV-1): the CORS seam must not use AllowOrigin::predicate (Host-capable)." >&2
    status=1
fi

# INV-2: the seam is build_cors_layer + AllowOrigin::list, fed from config.
if ! printf '%s' "${PROD_MAIN}" | grep -E 'fn build_cors_layer\(' >/dev/null; then
    echo "FAIL (VAU-010 INV-2): build_cors_layer seam is missing from main.rs." >&2
    status=1
fi
if ! printf '%s' "${PROD_MAIN}" | grep -E 'AllowOrigin::list' >/dev/null; then
    echo "FAIL (VAU-010 INV-2): the CORS seam must use AllowOrigin::list (exact allowlist match)." >&2
    status=1
fi
if ! printf '%s' "${PROD_MAIN}" \
    | grep -E 'build_cors_layer\(&state\.config\.server\.parsed_public_origins\(\)\)' >/dev/null; then
    echo "FAIL (VAU-010 INV-2): create_app must feed the CORS layer from parsed_public_origins()." >&2
    status=1
fi

# INV-2/INV-4: config carries the allowlist field + the fail-closed validator.
if ! grep -qE 'pub public_origins' "${CONFIG}"; then
    echo "FAIL (VAU-010 INV-2): ServerConfig.public_origins is missing from config.rs." >&2
    status=1
fi
if ! grep -qE 'fn parsed_public_origins' "${CONFIG}"; then
    echo "FAIL (VAU-010 INV-2): ServerConfig::parsed_public_origins is missing from config.rs." >&2
    status=1
fi

if [[ "${status}" -eq 0 ]]; then
    echo "OK: CORS origin decision is confined to the config allowlist; Host is never consulted (VAU-010)."
fi

exit "${status}"
