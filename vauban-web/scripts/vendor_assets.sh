#!/usr/bin/env bash
#
# vendor_assets.sh - Re-download the self-hosted front-end assets.
#
# Vauban serves every front-end dependency from its own /static/ tree so the
# browser never reaches a third-party CDN at runtime. This script documents the
# exact upstream URLs + pinned versions and refreshes the vendored copies under
# static/js/vendor and static/css/vendor. Run it from anywhere; paths are
# resolved relative to this script.
#
# NOTE: the Tailwind file is the *JIT runtime compiler* (the Play CDN bundle),
# not a pre-compiled stylesheet. Self-hosting it keeps the existing behaviour
# (utility classes compiled in the browser) without introducing a Node build.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATIC_DIR="$(cd "${SCRIPT_DIR}/../static" && pwd)"
JS_DIR="${STATIC_DIR}/js/vendor"
CSS_DIR="${STATIC_DIR}/css/vendor"

mkdir -p "${JS_DIR}" "${CSS_DIR}"

fetch() {
    local url="$1" dest="$2"
    echo "  ${dest}  <-  ${url}"
    curl -sS -L --fail --max-time 120 -o "${dest}" "${url}"
}

echo "Tailwind JIT 3.4.17"
fetch "https://cdn.tailwindcss.com/3.4.17" "${JS_DIR}/tailwindcss.js"

echo "htmx 1.9.12 (+ws +json-enc)"
fetch "https://unpkg.com/htmx.org@1.9.12/dist/htmx.min.js" "${JS_DIR}/htmx.min.js"
fetch "https://unpkg.com/htmx.org@1.9.12/dist/ext/ws.js" "${JS_DIR}/htmx-ext-ws.js"
fetch "https://unpkg.com/htmx.org@1.9.12/dist/ext/json-enc.js" "${JS_DIR}/htmx-ext-json-enc.js"

echo "Alpine.js 3.14.0 (standard build)"
fetch "https://unpkg.com/alpinejs@3.14.0/dist/cdn.min.js" "${JS_DIR}/alpine.min.js"

echo "xterm 5.5.0 (+fit 0.10.0 +web-links 0.11.0)"
fetch "https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/css/xterm.min.css" "${CSS_DIR}/xterm.min.css"
fetch "https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/lib/xterm.min.js" "${JS_DIR}/xterm.min.js"
fetch "https://cdn.jsdelivr.net/npm/@xterm/addon-fit@0.10.0/lib/addon-fit.min.js" "${JS_DIR}/xterm-addon-fit.min.js"
fetch "https://cdn.jsdelivr.net/npm/@xterm/addon-web-links@0.11.0/lib/addon-web-links.min.js" "${JS_DIR}/xterm-addon-web-links.min.js"

echo "Done. Vendored assets refreshed under ${STATIC_DIR}."
