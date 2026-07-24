#!/usr/bin/env bash
# Structural lint: Inspect Capture analyzer (+ etherparse) live in
# vauban-web-evidence, not under vauban-web/src/services/.
#
# Returns non-zero on the first violation.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REPO="$(cd "${ROOT}/.." && pwd)"
WEB_TOML="${ROOT}/Cargo.toml"
ANALYZER_DIR="${ROOT}/src/services/iacs_packet_analyzer"
EVIDENCE_ANALYZER="${REPO}/vauban-web-evidence/src/analyzer"
errors=0

if [[ -d "${ANALYZER_DIR}" ]]; then
    echo "[lint] ${ANALYZER_DIR} must not exist (moved to vauban-web-evidence)" >&2
    errors=1
fi

if [[ ! -d "${EVIDENCE_ANALYZER}" ]]; then
    echo "[lint] missing ${EVIDENCE_ANALYZER}" >&2
    errors=1
fi

if ! grep -qF 'vauban-web-evidence' "${WEB_TOML}"; then
    echo "[lint] vauban-web/Cargo.toml must depend on vauban-web-evidence" >&2
    errors=1
fi

if grep -qE '^etherparse\s*=' "${WEB_TOML}"; then
    echo "[lint] vauban-web must not depend on etherparse (lives in evidence)" >&2
    errors=1
fi

if ! grep -qE '^etherparse\s*=' "${REPO}/vauban-web-evidence/Cargo.toml"; then
    echo "[lint] vauban-web-evidence must depend on etherparse" >&2
    errors=1
fi

if ! grep -qF 'pub use vauban_web_evidence::analyzer as iacs_packet_analyzer' \
    "${ROOT}/src/services/mod.rs"; then
    echo "[lint] services/mod.rs must re-export evidence analyzer as iacs_packet_analyzer" >&2
    errors=1
fi

if [[ ! -f "${REPO}/vauban-web-evidence/src/hydrator/pipeline.rs" ]]; then
    echo "[lint] missing vauban-web-evidence hydrator pipeline" >&2
    errors=1
fi

if [[ ! -f "${ROOT}/src/services/recording_hydrator/adapters.rs" ]]; then
    echo "[lint] web must keep recording_hydrator adapters" >&2
    errors=1
fi

if [[ -f "${ROOT}/src/services/recording_hydrator.rs" ]]; then
    echo "[lint] monolith recording_hydrator.rs must be a directory module" >&2
    errors=1
fi

if [[ "$errors" -ne 0 ]]; then
    exit 1
fi
echo "[lint] web evidence crate invariants OK"
exit 0
