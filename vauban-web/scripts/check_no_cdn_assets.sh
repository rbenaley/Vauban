#!/usr/bin/env bash
# Structural lint: forbid runtime third-party CDN dependencies.
#
# Every front-end library (Tailwind JIT, htmx, Alpine.js, the xterm
# stack) is self-hosted under `vauban-web/static/js/vendor` and
# `vauban-web/static/css/vendor` and served same-origin from `/static/`.
# The browser must NEVER reach a third-party origin at runtime, so:
#
#   1. No template under `templates/**.html` may reference a CDN origin
#      (`cdn.tailwindcss.com`, `unpkg.com`, `cdn.jsdelivr.net`).
#   2. The production portion of `src/middleware/security.rs` (the CSP)
#      may not whitelist any CDN origin. The `#[cfg(test)]` module is
#      scanned out because it carries *negative* assertions that name the
#      forbidden origins on purpose.
#
# A non-zero exit code blocks CI on the first offending occurrence.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEMPLATE_DIR="${ROOT}/templates"
SECURITY_RS="${ROOT}/src/middleware/security.rs"

# CDN origins that must not appear at runtime.
CDN_ORIGINS=(
    "cdn.tailwindcss.com"
    "unpkg.com"
    "cdn.jsdelivr.net"
)

# Build an alternation regex: cdn\.tailwindcss\.com|unpkg\.com|...
PATTERN=""
for origin in "${CDN_ORIGINS[@]}"; do
    escaped="${origin//./\\.}"
    if [[ -z "${PATTERN}" ]]; then
        PATTERN="${escaped}"
    else
        PATTERN="${PATTERN}|${escaped}"
    fi
done

errors=0

if [[ ! -d "${TEMPLATE_DIR}" ]]; then
    echo "[lint] template directory not found: ${TEMPLATE_DIR}" >&2
    exit 2
fi

# Rule 1: no CDN origin in any template.
while IFS= read -r -d '' file; do
    while IFS=: read -r line_no line; do
        echo "[lint] ${file}:${line_no} -- runtime CDN reference; self-host under /static/js/vendor or /static/css/vendor" >&2
        echo "    > ${line}" >&2
        errors=$((errors + 1))
    done < <(grep -nE "${PATTERN}" "${file}" || true)
done < <(find "${TEMPLATE_DIR}" -type f -name "*.html" -print0)

# Rule 2: no CDN origin in the production portion of the CSP middleware.
# Scan only the lines BEFORE `#[cfg(test)]` so the negative test
# assertions naming the forbidden origins do not trip the lint.
if [[ -f "${SECURITY_RS}" ]]; then
    prod_portion="$(awk '/#\[cfg\(test\)\]/{exit} {print}' "${SECURITY_RS}")"
    while IFS=: read -r line_no line; do
        echo "[lint] ${SECURITY_RS}:${line_no} -- CDN origin in CSP; the policy must stay scoped to 'self'" >&2
        echo "    > ${line}" >&2
        errors=$((errors + 1))
    done < <(printf '%s\n' "${prod_portion}" | grep -nE "${PATTERN}" || true)
fi

if (( errors > 0 )); then
    echo "[lint] ${errors} runtime CDN reference(s) found." >&2
    exit 1
fi

echo "[lint] no runtime CDN dependency (templates + CSP are self-hosted)."
