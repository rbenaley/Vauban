#!/usr/bin/env bash
# Structural lint: enforce two HTMX/CSRF anti-regression rules in
# Askama templates.
#
# Both rules were learned from issue #24 (BUG-13: search bar on
# `/accounts/groups/{uuid}/members/add` was inert because its input
# carried no `name` attribute, so `hx-include="this"` serialized
# nothing). The same template had a sibling regression in the HTMX
# response handler -- it shipped `<input type="hidden" name="csrf_token" />`
# empty, expecting some out-of-band JS to fill it. That pattern is
# explicitly listed as FORBIDDEN in
# `.cursor/skills/front-end-design/SKILL.md` and would have silently
# broken the Add button as soon as BUG-13 was patched.
#
# Rules
# -----
#
# Rule 1 (HTMX input must be named): any `<input ...>` tag carrying any
# `hx-*` attribute MUST also carry a non-empty `name="..."`. Without it
# `hx-include` (whether `this`, a CSS selector, or a default) cannot
# serialize the field.
#
# Rule 2 (CSRF input must be populated, canonical channels only):
# any `<input ... name="csrf_token" ...>` MUST carry exactly one of the
# two CANONICAL populating attributes:
#
#   - `value="..."` (server-side injection -- canonical for login/MFA
#     where the token is rendered into the page by Askama),
#   - `x-model="token"` (Alpine `csrf` component, canonical for
#     post-auth pages -- the `csrf` component encapsulates the cookie
#     read, see front-end-design SKILL).
#
# Inline `:value="document.cookie..."` / `x-bind:value="..."` reading
# the cookie directly from HTML is REJECTED. It is functionally
# equivalent to vanilla-JS cookie reading and bypasses the `csrf`
# Alpine component, which is the single source of truth for CSRF
# token reading. If the cookie name or shape ever changes, the
# canonical component is updated once; inline readers break silently.
#
# Rule 3 (no inline cookie reads in templates): `document.cookie`
# MUST NOT appear in any template. The `csrf` Alpine component in
# `static/js/vauban-components.js` is the single reader. This catches
# `hx-vals="js:{csrf_token: document.cookie.match(...)}"` (the same
# anti-pattern dressed up as an HTMX evaluator) and any future inline
# cookie peek added to a template.
#
# Rules 1 and 2 tolerate multi-line `<input>` tags (we coalesce
# attributes until we see the closing `>` before applying the regex).
#
# Returns non-zero on the first offending occurrence so it can plug into
# CI.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEMPLATE_DIR="${ROOT}/templates"

if [[ ! -d "${TEMPLATE_DIR}" ]]; then
    echo "[lint] template directory not found: ${TEMPLATE_DIR}" >&2
    exit 2
fi

errors=0

# Coalesce multi-line `<input ...>` tags to a single logical line per
# tag. Emits one normalized line per `<input>` tag, prefixed with the
# original starting line number for diagnostics.
#
# Output format: `<file>:<lineno>:<normalized-input-tag>`
coalesce_input_tags() {
    local file="$1"
    awk -v f="$file" '
        /<input\b/ {
            in_tag = 1
            start_line = NR
            buf = ""
        }
        in_tag {
            buf = buf " " $0
            if (index($0, ">") > 0) {
                gsub(/[[:space:]]+/, " ", buf)
                sub(/^ +/, "", buf)
                printf "%s:%d:%s\n", f, start_line, buf
                in_tag = 0
                buf = ""
            }
        }
    ' "$file"
}

# ---------------------------------------------------------------------------
# Rule 1: HTMX-bearing input must carry a non-empty name.
# ---------------------------------------------------------------------------
while IFS= read -r -d '' file; do
    while IFS= read -r entry; do
        # Strip the file:lineno: prefix to get the normalized tag.
        tag="${entry#*:*:}"
        # Does this tag carry any hx-* attribute?
        if [[ "$tag" =~ [[:space:]]hx-[a-zA-Z]+= ]]; then
            # Does it have a non-empty name="..." (not just name="")?
            if ! [[ "$tag" =~ [[:space:]]name=\"[^\"]+\" ]]; then
                location="${entry%%:*}"
                lineno="${entry#*:}"; lineno="${lineno%%:*}"
                echo "[lint] ${location}:${lineno}: HTMX input is missing a non-empty name=\"...\":" >&2
                echo "        ${tag}" >&2
                errors=1
            fi
        fi
    done < <(coalesce_input_tags "$file")
done < <(find "${TEMPLATE_DIR}" -type f -name '*.html' -print0)

# ---------------------------------------------------------------------------
# Rule 2: csrf_token input must be populated via a canonical channel only
#         (server-rendered value="..." OR Alpine x-model="token").
# ---------------------------------------------------------------------------
while IFS= read -r -d '' file; do
    while IFS= read -r entry; do
        tag="${entry#*:*:}"
        if [[ "$tag" =~ [[:space:]]name=\"csrf_token\" ]]; then
            has_value=0
            has_xmodel=0
            has_inline_bind=0
            if [[ "$tag" =~ [[:space:]]value=\"[^\"]+\" ]]; then
                has_value=1
            fi
            if [[ "$tag" =~ [[:space:]]x-model=\"token\" ]]; then
                has_xmodel=1
            fi
            if [[ "$tag" =~ [[:space:]](:value|x-bind:value)=\" ]]; then
                has_inline_bind=1
            fi

            location="${entry%%:*}"
            lineno="${entry#*:}"; lineno="${lineno%%:*}"

            if [[ $has_inline_bind -eq 1 ]]; then
                echo "[lint] ${location}:${lineno}: csrf_token uses inline :value/x-bind:value (forbidden):" >&2
                echo "        ${tag}" >&2
                echo "        Migrate to: <form ... x-data=\"csrf\"> + <input type=\"hidden\" name=\"csrf_token\" x-model=\"token\" />" >&2
                errors=1
            elif [[ $has_value -eq 0 && $has_xmodel -eq 0 ]]; then
                echo "[lint] ${location}:${lineno}: csrf_token input is empty (need either server value=\"...\" or x-model=\"token\"):" >&2
                echo "        ${tag}" >&2
                errors=1
            fi
        fi
    done < <(coalesce_input_tags "$file")
done < <(find "${TEMPLATE_DIR}" -type f -name '*.html' -print0)

# ---------------------------------------------------------------------------
# Rule 3: no `document.cookie` reads in templates. The `csrf` Alpine
# component in static/js/vauban-components.js is the single reader.
# Catches `hx-vals="js:{csrf_token: document.cookie.match(...)}"` and any
# future inline cookie peek dressed up as an Alpine/HTMX evaluator.
# ---------------------------------------------------------------------------
while IFS= read -r -d '' file; do
    while IFS=: read -r lineno content; do
        echo "[lint] ${file}:${lineno}: 'document.cookie' must not appear in a template (use <form x-data=\"csrf\">):" >&2
        echo "        ${content}" >&2
        errors=1
    done < <(grep -nF 'document.cookie' "$file" || true)
done < <(find "${TEMPLATE_DIR}" -type f -name '*.html' -print0)

if [[ $errors -ne 0 ]]; then
    echo >&2
    echo "[lint] HTMX / CSRF input rules violated. See:" >&2
    echo "       - vauban-web/scripts/check_htmx_input_name.sh" >&2
    echo "       - .cursor/skills/front-end-design/SKILL.md (CSRF section)" >&2
    echo "       - GitHub issue #24 (BUG-13)" >&2
    exit 1
fi

echo "[lint] no HTMX-without-name, empty/inline csrf_token, or inline cookie reads detected"
