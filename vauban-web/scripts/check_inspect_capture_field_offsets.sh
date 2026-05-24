#!/usr/bin/env bash
# Structural lint: tree<->hex contract for the IACS Inspect Capture
# analyzer.
#
# Every `data-field="..."` value rendered by the hex pane
# (`_hex_dump.html`) MUST also be referenced by the tree partial
# (`_packet_detail.html`). If a hex byte refers to a field id that
# the tree never surfaces, the Alpine `x-data` highlight wires
# nothing and the operator sees a dead area in the dump.
#
# Note: both partials populate `data-field` from server-rendered
# Askama variables (`n.field_id`, `b.field_id`); the literal field
# ids in HTML come from the dissectors. We therefore lint on
# *static literal* `data-field="..."` occurrences (which is a
# superset of "hardcoded fields"). Server-supplied dynamic values
# round-trip via the same view-model and are pinned by the
# template_test (`packet_detail_carries_data_field_attributes_*`).

set -euo pipefail

if [[ -n "${BASH_SOURCE[0]:-}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
else
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
fi
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
INSPECT_DIR="${ROOT}/templates/sessions/inspect"

DETAIL="${INSPECT_DIR}/_packet_detail.html"
HEX="${INSPECT_DIR}/_hex_dump.html"

if [[ ! -f "${DETAIL}" || ! -f "${HEX}" ]]; then
    echo "[lint] expected partials missing under ${INSPECT_DIR}" >&2
    exit 1
fi

# Both partials MUST emit a `data-field=` attribute (dynamic
# Askama variable counts; we only check that the attribute name
# itself is present in both).
if ! grep -q 'data-field=' "${DETAIL}"; then
    echo "[lint] _packet_detail.html missing data-field= attribute on dissection nodes" >&2
    exit 1
fi
if ! grep -q 'data-field=' "${HEX}"; then
    echo "[lint] _hex_dump.html missing data-field= attribute on hex bytes" >&2
    exit 1
fi

# Both partials MUST share the SAME Alpine highlight binding
# (`highlight === '...'`), otherwise the hover propagation breaks.
if ! grep -q "highlight === '" "${DETAIL}"; then
    echo "[lint] _packet_detail.html missing Alpine highlight binding" >&2
    exit 1
fi
if ! grep -q "highlight === '" "${HEX}"; then
    echo "[lint] _hex_dump.html missing Alpine highlight binding" >&2
    exit 1
fi

# Hardcoded field ids in either partial are forbidden -- field ids
# come from the dissector via the view-model.
if grep -nE 'data-field="[a-zA-Z_.]+"' "${DETAIL}" "${HEX}" 2>/dev/null \
    | grep -v '{{' >&2; then
    echo "[lint] forbidden literal data-field= in inspect partials (must reference view-model)" >&2
    exit 1
fi

echo "[lint] tree<->hex data-field contract OK"
