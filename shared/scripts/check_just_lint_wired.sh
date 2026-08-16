#!/usr/bin/env bash
# Pin: `just validate` must invoke `just lint` so structural checks are not optional.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
JUST="${ROOT}/Justfile"

if [[ ! -f "${JUST}" ]]; then
    echo "[lint] missing Justfile" >&2
    exit 1
fi

if ! grep -qE '^validate:' "${JUST}"; then
    echo "[lint] Justfile has no validate recipe" >&2
    exit 1
fi

# The validate body must call just lint (not merely mention it in a comment).
if ! awk '/^validate:/{p=1;next} p && /^[a-zA-Z]/{exit} p' "${JUST}" | grep -q 'just lint'; then
    echo "[lint] just validate must run \`just lint\`" >&2
    exit 1
fi

echo "[lint] just validate is wired to just lint"
