#!/usr/bin/env bash
# Structural lint: enforce mobile-first responsive design rules in Askama
# templates.
#
# We learned the hard way (issue #14: Users table overflows on iPhone) that
# the only reliable defense against horizontal-overflow regressions is a
# script that fails CI when a template re-introduces a forbidden pattern.
#
# The rules below codify what the responsive overhaul (Vague 1/2/3) shipped:
#
#   1. Any `<table>` MUST sit inside a parent that scrolls horizontally.
#      We accept either `overflow-x-auto` on a wrapper or `overflow-auto`
#      on the table itself; bare `overflow-hidden` next to a table is the
#      classic root-cause of the bug.
#   2. Page titles (`<h1>` / `<h2>`) MUST NOT use a fixed `text-2xl` or
#      `text-3xl` without a mobile fallback (`text-xl sm:text-2xl ...`)
#      so they don't blow up the viewport on phones.
#   3. Toast / floating containers MUST NOT hard-code `w-96` (24rem). On a
#      375px iPhone screen this overflows; use `w-full max-w-md` (or the
#      `sm:w-96` breakpoint variant) instead.
#
# Returns non-zero on the first offending occurrence so it can plug into CI.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEMPLATE_DIR="${ROOT}/templates"

if [[ ! -d "${TEMPLATE_DIR}" ]]; then
    echo "[lint] template directory not found: ${TEMPLATE_DIR}" >&2
    exit 2
fi

errors=0

# ---------------------------------------------------------------------------
# Rule 1: every <table> needs a horizontally-scrollable ancestor.
# We approximate "ancestor" by checking that the same file contains either
# `overflow-x-auto` or `overflow-auto`. The rule is structural, not
# DOM-aware, but in practice every list view that hosts a table also
# carries the wrapper class somewhere on the same template file.
# ---------------------------------------------------------------------------
while IFS= read -r -d '' file; do
    if grep -q '<table' "$file"; then
        if ! grep -Eq 'overflow-x-auto|overflow-auto' "$file"; then
            echo "[lint] ${file}: <table> without overflow-x-auto wrapper" >&2
            errors=1
        fi
    fi
done < <(find "${TEMPLATE_DIR}" -type f -name '*.html' -print0)

# ---------------------------------------------------------------------------
# Rule 2: page titles must scale down on mobile.
# Forbidden: a class attribute that pins the title to a desktop-only size
# without any `sm:`/`md:`/`lg:` step. We constrain the search to <h1>/<h2>
# tags so that ordinary section headers (text-lg, text-sm in <h3>) are not
# affected.
# ---------------------------------------------------------------------------
PATTERN_TITLE_FIXED='<h[12][[:space:]][^>]*class="[^"]*\btext-(2xl|3xl)\b[^"]*"'
PATTERN_RESPONSIVE='\b(sm|md|lg|xl):text-'

while IFS= read -r -d '' file; do
    while IFS= read -r line; do
        if [[ "$line" =~ $PATTERN_TITLE_FIXED ]]; then
            if ! [[ "$line" =~ $PATTERN_RESPONSIVE ]]; then
                echo "[lint] ${file}: <h1>/<h2> uses fixed text-2xl/3xl without responsive step" >&2
                echo "        ${line}" >&2
                errors=1
            fi
        fi
    done < "$file"
done < <(find "${TEMPLATE_DIR}" -type f -name '*.html' -print0)

# ---------------------------------------------------------------------------
# Rule 3: floating containers must not pin a fixed `w-96` (= 24rem) at the
# base breakpoint -- they overflow a 375px iPhone screen. The acceptable
# form is `w-full max-w-md` (with optional `sm:w-96`).
# ---------------------------------------------------------------------------
PATTERN_W96='class="[^"]*\bw-96\b[^"]*"'

while IFS= read -r -d '' file; do
    while IFS= read -r line; do
        if [[ "$line" =~ $PATTERN_W96 ]]; then
            # Allow if it is gated behind a breakpoint (e.g. sm:w-96).
            if ! [[ "$line" =~ \b(sm|md|lg|xl):w-96\b ]] || \
               [[ "$line" =~ \bw-96[[:space:]] ]] || \
               [[ "$line" =~ \"w-96 ]]; then
                echo "[lint] ${file}: hard-coded w-96 will overflow on small viewports" >&2
                echo "        ${line}" >&2
                errors=1
            fi
        fi
    done < "$file"
done < <(find "${TEMPLATE_DIR}" -type f -name '*.html' -print0)

if [[ $errors -ne 0 ]]; then
    echo >&2
    echo "[lint] Responsive template rules violated. See:" >&2
    echo "       - vauban-web/scripts/check_responsive_templates.sh" >&2
    echo "       - .cursor/rules/responsive-templates.mdc" >&2
    exit 1
fi

echo "[lint] no responsive-template regressions detected"
