#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="${ROOT}/src"
errors=0

fail() {
    echo "[lint] $*" >&2
    errors=1
}

recording_block="$(awk '/Receive encoded H.264 frames/{capture=1} capture{print} /let msg = Message::RdpVideoFrame/{exit}' "${SRC}/session.rs")"
if printf '%s' "${recording_block}" | rg -q 'try_send\(.*RdpVideoFrame|audit_msg.*RdpVideoFrame'; then
    fail "RDP recording path must not try_send RdpVideoFrame to audit"
fi

if ! rg -q 'RecordingFileRequest' "${SRC}/main.rs"; then
    fail "vauban-proxy-rdp must lease segment FDs via RecordingFileRequest"
fi

if ! rg -q 'RdpRecordingWriter|Fmp4Writer' "${SRC}"; then
    fail "vauban-proxy-rdp must own a local fMP4 writer"
fi

if ! rg -q 'provide_segment_file' "${SRC}/session.rs"; then
    fail "resolution changes must lease and install a new segment FD"
fi

if ! rg -q 'segments: seal.segments' "${SRC}/session.rs"; then
    fail "RdpRecordingEnd must carry proxy seal segment metadata"
fi

if [[ "${errors}" -ne 0 ]]; then
    exit 1
fi
echo "[lint] rdp recording FD invariants OK"
