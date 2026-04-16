#!/usr/bin/env bash
# Structural lint: forbid is_staff/is_superuser usage as authorization gates
# inside Askama templates.
#
# Templates may still *display* user.is_staff / user.is_superuser (badges,
# account-management forms) but they MUST NOT use them inside `{% if ... %}`
# directives to hide or reveal actionable controls. The canonical gate is the
# Casbin-backed PermissionContext, exposed as `sc.perms.*` on the sidebar and
# `perms.*` on per-page templates.
#
# Returns non-zero on the first offending occurrence so it can plug into CI.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEMPLATE_DIR="${ROOT}/templates"

if [[ ! -d "${TEMPLATE_DIR}" ]]; then
    echo "[lint] template directory not found: ${TEMPLATE_DIR}" >&2
    exit 2
fi

# We deliberately do NOT forbid showing role badges or form checkboxes built
# from `profile.is_staff` / `user_data.is_superuser` / etc., which describe
# a *third-party* entity rendered for display. We forbid only patterns that
# look like the acting user's privilege check — those silently bypass any
# Casbin policy customization (see issue #1):
#
#   1. `is_staff || is_superuser` (or the symmetric form) inside any
#      `{% if %}` / `{% elif %}` directive: that combination IS the legacy
#      "either flavour of admin" gate.
#   2. `sc.user.is_staff` / `sc.user.is_superuser` inside an `if`/`elif`:
#      the sidebar context already exposes `sc.perms.*` for every Casbin
#      permission, gating on `sc.user.*` defeats the purpose.

errors=0

# Pattern 1: combined is_staff/is_superuser gate inside an if/elif.
PATTERN_COMBINED='\{%-?[[:space:]]*(if|elif)\b[^%]*\b(is_staff[[:space:]]*\|\|[[:space:]]*is_superuser|is_superuser[[:space:]]*\|\|[[:space:]]*is_staff)\b[^%]*-?%\}'

if grep -REn --include='*.html' "${PATTERN_COMBINED}" "${TEMPLATE_DIR}"; then
    echo >&2
    echo "[lint] forbidden 'is_staff || is_superuser' gate above ^^." >&2
    errors=1
fi

# Pattern 2: sc.user.is_(staff|superuser) inside if/elif.
PATTERN_SC_USER='\{%-?[[:space:]]*(if|elif)\b[^%]*\bsc\.user\.(is_staff|is_superuser)\b[^%]*-?%\}'

if grep -REn --include='*.html' "${PATTERN_SC_USER}" "${TEMPLATE_DIR}"; then
    echo >&2
    echo "[lint] forbidden gate on sc.user.is_staff/is_superuser above ^^." >&2
    errors=1
fi

if [[ $errors -ne 0 ]]; then
    echo >&2
    echo "[lint] Use sc.perms.<resource>_<action> (PermissionContext) instead." >&2
    echo "[lint] See vauban-web/src/auth/permissions.rs and AGENTS.md." >&2
    exit 1
fi

echo "[lint] no forbidden role-based template gates detected"
