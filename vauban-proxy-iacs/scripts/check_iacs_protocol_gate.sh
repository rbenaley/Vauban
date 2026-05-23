#!/usr/bin/env bash
# check_iacs_protocol_gate.sh
#
# Defence-in-depth lint: the EWS -> asset relay leg MUST go through
# the protocol recognition gate (`filtered_copy_with_counter`), not
# blind `copy_with_counter`.
#
# Pinned by:
#   - vauban-proxy-iacs/tests/per_asset_target_test.rs
#   - vauban-proxy-iacs/tests/protocol_gate_adversarial_test.rs

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SERVER="$ROOT/src/server.rs"
GATE="$ROOT/src/protocol_gate.rs"
AUTH="$ROOT/src/auth.rs"

if [[ ! -f "$SERVER" ]]; then
    echo "FAIL: $SERVER not found" >&2
    exit 1
fi

fail=0

if ! grep -q 'filtered_copy_with_counter' "$SERVER"; then
    echo "FAIL: spawn_relay MUST call filtered_copy_with_counter on the EWS -> asset leg" >&2
    fail=1
fi

if grep -E 'copy_with_counter\s*\(\s*reader_ssh' "$SERVER"; then
    echo "FAIL: spawn_relay MUST NOT call copy_with_counter directly on reader_ssh (EWS -> asset)" >&2
    fail=1
fi

if ! grep -q 'ExpectedProfile::from_industrial_label' "$SERVER"; then
    echo "FAIL: spawn_relay MUST derive ExpectedProfile from industrial_protocol" >&2
    fail=1
fi

if grep -q 'dead_code.*industrial_protocol' "$AUTH"; then
    echo "FAIL: industrial_protocol MUST participate in the gate (no dead_code allow)" >&2
    fail=1
fi

if [[ ! -f "$GATE" ]]; then
    echo "FAIL: missing protocol_gate.rs module" >&2
    fail=1
fi

if [[ -f "$GATE" ]] && ! grep -q 'sleep_until' "$GATE"; then
    echo "FAIL: protocol gate NeedMoreData select MUST arm sleep_until(deadline)" >&2
    fail=1
fi

if [[ "$fail" -ne 0 ]]; then
    exit 1
fi

echo "OK: IACS protocol gate lint passed"
