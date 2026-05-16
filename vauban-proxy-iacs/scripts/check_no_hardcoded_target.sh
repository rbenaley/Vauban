#!/usr/bin/env bash
# check_no_hardcoded_target.sh
#
# Lint script: forbid the legacy IACS MVP fixed target literal
# (`127.0.0.1:4321`) in `vauban-proxy-iacs/src/`. The pre-Lot-3 code
# unconditionally connected to that loopback address; per-asset
# resolution is now enforced via the supervisor SCM_RIGHTS broker
# (`asset.hostname:asset.port`).
#
# A reintroduction of the literal would silently revert the per-asset
# target resolution (the per-session `validate_target` would still
# pass for any EWS that happened to request `127.0.0.1:4321`, masking
# the regression). This script is invoked from `cargo test` via the
# matching include_str! / find pattern in the proxy-iacs unit tests
# AND from CI to fail the build before any test runs.

set -euo pipefail

SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)/src"

if [[ ! -d "$SRC_DIR" ]]; then
    echo "ERROR: $SRC_DIR does not exist (lint must run from the workspace)" >&2
    exit 2
fi

# Forbid the *literal* dotted-quad + port combination. Comments and
# tests inside the src/ tree are allowed to mention the legacy target
# in prose ONLY if the form is split (e.g. "127.0.0.1" + ":4321") so
# this exact-byte grep stays meaningful.
NEEDLE='127.0.0.1:4321'

if grep -rn --include='*.rs' -F -- "$NEEDLE" "$SRC_DIR" >&2; then
    echo "ERROR: legacy IACS MVP target literal '$NEEDLE' found in" \
         "vauban-proxy-iacs/src/. Per-asset target resolution is the" \
         "Lot 3 contract; tunnels MUST resolve asset.hostname:" \
         "asset.port at session creation, not bind a global default." >&2
    exit 1
fi

echo "ok: no hardcoded IACS target literal in vauban-proxy-iacs/src/"
