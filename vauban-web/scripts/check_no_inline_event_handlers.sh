#!/usr/bin/env bash
# Structural lint: forbid inline DOM event-handler attributes
# (`onsubmit=`, `onclick=`, `onchange=`, ... any `on*=`) in every
# Askama template under `templates/`.
#
# Why (CSP hardening, July 2026): the production CSP is
# `script-src 'self' 'unsafe-eval'` -- NO `'unsafe-inline'`. Browsers
# therefore silently refuse to execute inline handler attributes. The
# audit found 7 destructive forms whose `onsubmit="return confirm(...)"`
# guard was dead code: a single click deleted the resource with NO
# confirmation dialog (secrets, secret groups, secret access rules,
# asset access rules, EWS offboard x3). The fix migrated them to the
# BUG-12 HTMX + styled `deleteConfirm` modal pattern; this lint keeps
# the dead-guard pattern from ever coming back.
#
# Detection notes (battle-tested against evasions):
#   - case-insensitive (`ONSUBMIT=`, `OnClick=` are equivalent in HTML),
#   - tolerates whitespace between the attribute name and `=`
#     (`onsubmit = "..."` is valid HTML),
#   - only fires when the attribute is preceded by whitespace, a quote
#     or a slash (attribute position), so Alpine `x-on:submit`,
#     HTMX `hx-on:*`, `@submit`, and data attributes like
#     `data-online=` never false-positive.
#
# The same detector is mirrored in Rust (with proptest coverage) in
# `tests/web/no_inline_event_handlers_test.rs`; that test also executes
# this script so CI and `cargo test` stay in lock-step.

set -euo pipefail

if [[ -n "${BASH_SOURCE[0]:-}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
else
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
fi
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TEMPLATE_DIR="${ROOT}/templates"

if [[ ! -d "${TEMPLATE_DIR}" ]]; then
    echo "[lint] template directory not found: ${TEMPLATE_DIR}" >&2
    exit 2
fi

# Attribute position = start-of-line or whitespace or quote or `/`
# (self-closing tail). `on[a-z]+` then optional whitespace then `=`.
# `grep -iE` gives us HTML's case-insensitivity for free.
PATTERN='(^|[[:space:]"'"'"'/])on[a-z]+[[:space:]]*='

violations=0
while IFS= read -r -d '' file; do
    if grep -niE "${PATTERN}" "${file}" >/dev/null; then
        echo "[lint] inline event handler in ${file}:" >&2
        grep -niE "${PATTERN}" "${file}" >&2
        violations=$((violations + 1))
    fi
done < <(find "${TEMPLATE_DIR}" -type f -name '*.html' -print0)

if [[ ${violations} -gt 0 ]]; then
    echo >&2
    echo "[lint] ${violations} template(s) carry inline on*= event handlers." >&2
    echo "       The CSP (script-src 'self') silently disables them -- the handler" >&2
    echo "       is DEAD CODE in production. Use the BUG-12 pattern instead:" >&2
    echo "         <form hx-post=\"...\" hx-confirm=\"...\"" >&2
    echo "               data-confirm-title=\"...\" data-confirm-message=\"...\"" >&2
    echo "               @htmx:confirm.prevent=\"\$store.deleteConfirm.openWith({...})\">" >&2
    echo "       See vauban-web/tests/web/no_inline_event_handlers_test.rs" >&2
    exit 1
fi

echo "[lint] no inline on*= event handlers found in templates/"
