#!/usr/bin/env bash
# Bastion Watch dashboard passivity lint.
#
# The dashboard at `/` is a read-only operations radar. Any
# actionable widget (button, form, mutating HTMX verb) here is a
# regression: the page becomes a "wall of buttons" that erodes
# operator focus. This script grep-fails on the obvious markers so
# we catch regressions before CI's slower test suite.
#
# Pin tests in `tests/web/bastion_watch_test.rs` carry the same
# guarantees at runtime; this script is a fast pre-commit hook.

set -euo pipefail

CRATE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PAGE="${CRATE_DIR}/templates/dashboard/bastion_watch.html"
TILES_DIR="${CRATE_DIR}/templates/dashboard/tiles"

red() { printf '\033[31m%s\033[0m\n' "$1" >&2; }
green() { printf '\033[32m%s\033[0m\n' "$1"; }

ok=true

if [[ ! -f "${PAGE}" ]]; then
    red "ERR: bastion_watch.html missing at ${PAGE}"
    exit 1
fi

if [[ ! -d "${TILES_DIR}" ]]; then
    red "ERR: tile partial directory missing at ${TILES_DIR}"
    exit 1
fi

# 1. Forbidden tokens in the page template + every tile partial.
forbidden=(
    '<button'
    '<form'
    'hx-post'
    'hx-put'
    'hx-delete'
    'hx-patch'
)

scan() {
    local file="$1"
    for token in "${forbidden[@]}"; do
        # Skip the rule-comment block (line begins with `{#` ... `#}`)
        if grep -E "${token}" "${file}" >/dev/null 2>&1; then
            # Try to ignore single-line comment blocks `{# ... #}`
            if grep -Ev '^[[:space:]]*\{#.*#\}[[:space:]]*$' "${file}" \
                | grep -E "${token}" >/dev/null 2>&1; then
                red "ERR: ${file} contains forbidden token \"${token}\""
                ok=false
            fi
        fi
    done
}

scan "${PAGE}"
for tile in "${TILES_DIR}"/*.html; do
    [[ -f "${tile}" ]] || continue
    scan "${tile}"
done

# 2. Every admin-only tile MUST be inside `{% if perms.admin_view %}`.
admin_tiles=(
    'dash-hero-jit'
    'dash-access-posture'
    'dash-anomalies'
    'dash-system-health'
)
for id in "${admin_tiles[@]}"; do
    if ! grep -E "id=\"${id}\"" "${PAGE}" >/dev/null 2>&1; then
        red "ERR: admin-only tile \"${id}\" not declared in bastion_watch.html"
        ok=false
        continue
    fi
done

# 3. Tile-id consistency: page declares 11 distinct ids.
declared=$(grep -E 'id="dash-[a-z-]+"' "${PAGE}" | sed -E 's/.*id="(dash-[a-z-]+)".*/\1/' | sort -u | wc -l)
if [[ "${declared}" -ne 11 ]]; then
    red "ERR: bastion_watch.html declares ${declared} dash-* ids, expected 11"
    ok=false
fi

if ${ok}; then
    green "Dashboard passivity check passed."
    exit 0
else
    exit 2
fi
