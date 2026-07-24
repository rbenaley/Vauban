#!/usr/bin/env bash
# Structural lint: RDP recording media is proxy-owned via RecordingFileRequest FD.
# Uses grep (not rg) so cargo-test sandboxes without ripgrep in PATH still pass.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="${ROOT}/src"
errors=0

fail() {
    echo "[lint] $*" >&2
    errors=1
}

recording_block="$(awk '/Receive encoded H.264 frames/{capture=1} capture{print} /let msg = Message::RdpVideoFrame/{exit}' "${SRC}/session.rs")"
if printf '%s' "${recording_block}" | grep -Eq 'try_send\(.*RdpVideoFrame|audit_msg.*RdpVideoFrame'; then
    fail "RDP recording path must not try_send RdpVideoFrame to audit"
fi

if ! grep -Eq 'RecordingFileRequest' "${SRC}/main.rs"; then
    fail "vauban-proxy-rdp must lease segment FDs via RecordingFileRequest"
fi

if ! grep -REq --include='*.rs' 'RdpRecordingWriter|Fmp4Writer' "${SRC}"; then
    fail "vauban-proxy-rdp must own a local fMP4 writer"
fi

if ! grep -Eq 'provide_segment_file' "${SRC}/session.rs"; then
    fail "resolution changes must lease and install a new segment FD"
fi

if ! grep -Eq 'segments: seal.segments' "${SRC}/session.rs"; then
    fail "RdpRecordingEnd must carry proxy seal segment metadata"
fi

if [[ "${errors}" -ne 0 ]]; then
    exit 1
fi
echo "[lint] rdp recording FD invariants OK"
