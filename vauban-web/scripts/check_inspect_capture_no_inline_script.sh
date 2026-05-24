#!/usr/bin/env bash
# Structural lint: forbid inline `<script>` tags inside the
# `templates/sessions/inspect/` folder.
#
# The IACS Inspect Capture analyzer is intentionally pure HTMX +
# Tailwind + a tiny declarative Alpine `x-data` (~10 lines). Any
# `<script>` tag that creeps in would either:
#
#   - bypass the project-wide CSP (`script-src` does not allow
#     `'unsafe-inline'`; only `'unsafe-eval'` is whitelisted for
#     Alpine declarative bindings), OR
#   - duplicate behaviour that already lives in HTMX attributes
#     (hx-get / hx-target / hx-swap / hx-include / hx-push-url).
#
# This script fails on the first occurrence and is wired into CI
# next to `check_responsive_templates.sh`.

set -euo pipefail

if [[ -n "${BASH_SOURCE[0]:-}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
else
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
fi
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
INSPECT_DIR="${ROOT}/templates/sessions/inspect"

if [[ ! -d "${INSPECT_DIR}" ]]; then
    echo "[lint] inspect template directory not found: ${INSPECT_DIR}" >&2
    exit 1
fi

violations=0
while IFS= read -r -d '' file; do
    # Match either an opening `<script` tag or the closing `</script>`.
    if grep -nE '<script[ >]|</script>' "${file}" >/dev/null; then
        echo "[lint] forbidden inline <script> in ${file}:" >&2
        grep -nE '<script[ >]|</script>' "${file}" >&2
        violations=$((violations + 1))
    fi
done < <(find "${INSPECT_DIR}" -type f -name '*.html' -print0)

if [[ ${violations} -gt 0 ]]; then
    echo "[lint] ${violations} template(s) contain inline <script>; remove them and use HTMX/Alpine attributes instead." >&2
    exit 1
fi

echo "[lint] no inline <script> found in templates/sessions/inspect/"
