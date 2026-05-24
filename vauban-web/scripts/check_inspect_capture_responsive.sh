#!/usr/bin/env bash
# Structural lint: every Askama template under
# `templates/sessions/inspect/` MUST declare at least one Tailwind
# breakpoint class on its top-level container so the page stays
# usable from 375px (iPhone) to 1440px+ (desktop).
#
# This is a complement to `check_responsive_templates.sh` -- the
# parent lint catches global anti-patterns (`w-96` toasts, fixed
# `text-3xl` titles, ...); this one verifies the inspect surface
# specifically opts into the responsive-templates rule.

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
    if ! grep -qE '\b(sm|md|lg|xl):' "${file}"; then
        echo "[lint] ${file} carries no responsive breakpoint class (sm:/md:/lg:/xl:)" >&2
        violations=$((violations + 1))
    fi
done < <(find "${INSPECT_DIR}" -type f -name '*.html' -print0)

if [[ ${violations} -gt 0 ]]; then
    echo "[lint] ${violations} inspect template(s) lack a responsive breakpoint." >&2
    exit 1
fi

echo "[lint] every inspect template carries at least one responsive breakpoint"
