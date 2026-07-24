#!/usr/bin/env bash
# Structural lint: SSH recording media is proxy-owned via RecordingFileRequest FD.
# Returns non-zero on the first violation.
# Uses grep (not rg) so cargo-test sandboxes without ripgrep in PATH still pass.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="${ROOT}/src"
errors=0

fail() {
    echo "[lint] $*" >&2
    errors=1
}

if grep -REq --include='*.rs' 'SshRecordingData' "${SRC}"; then
    fail "vauban-proxy-ssh must not send SshRecordingData (media is local FD)"
fi

if grep -REq --include='*.rs' 'try_send_recording|fn try_send_recording' "${SRC}"; then
    fail "vauban-proxy-ssh must not try_send recording payloads to audit"
fi

if ! grep -REq --include='*.rs' 'RecordingFileRequest' "${SRC}"; then
    fail "vauban-proxy-ssh must lease recording FDs via RecordingFileRequest"
fi

if ! grep -REq --include='*.rs' 'SshCastWriter|ssh_cast_writer' "${SRC}"; then
    fail "vauban-proxy-ssh must own an asciicast writer (ssh_cast_writer)"
fi

if ! grep -Eq 'blake3_hex' "${SRC}/session_manager.rs"; then
    fail "SshRecordingEnd path must include blake3_hex seal stats"
fi

if [[ "$errors" -ne 0 ]]; then
    exit 1
fi
echo "[lint] ssh recording FD invariants OK"
exit 0
