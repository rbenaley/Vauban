#!/usr/bin/env bash
# Structural invariants for browser timezone display surface.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "check_display_tz: $*" >&2
  exit 1
}

TZ="src/tz.rs"
ADMIN_DOCS="src/app/admin/docs.rs"
ADMIN_DOC="src/app/admin/docs/doc.rs"
CLIENT_DOC="src/app/org/docs/doc.rs"

[[ -f "$TZ" ]] || fail "missing $TZ"

grep -n 'VCP_TZ_COOKIE' "$TZ" >/dev/null || fail "$TZ must define VCP_TZ_COOKIE"
grep -n 'fn browser_tz' "$TZ" >/dev/null || fail "$TZ must define browser_tz"
grep -n 'fn format_local' "$TZ" >/dev/null || fail "$TZ must define format_local"
grep -n 'fn format_unix_local' "$TZ" >/dev/null || fail "$TZ must define format_unix_local"

# Admin docs edit page shows localized updated_at (list has no UPDATED column).
grep -n 'format_unix_local\|format_local' "$ADMIN_DOC" >/dev/null \
  || fail "$ADMIN_DOC must format dates via format_unix_local / format_local"
grep -n 'browser_tz' "$ADMIN_DOC" >/dev/null || fail "$ADMIN_DOC must call browser_tz"

# Forbid naked chrono format on UTC for display in admin docs surfaces.
if grep -nE '\.format\("%Y-%m-%d %H:%M' "$ADMIN_DOCS" "$ADMIN_DOC" >/dev/null 2>&1; then
  fail "admin docs must not use naked UTC .format for HTML display"
fi

grep -n 'format_unix_local\|format_local' "$CLIENT_DOC" >/dev/null \
  || fail "$CLIENT_DOC must localize updated_at"

# Browser cookie setter (first-party asset).
test -f assets/vcp_tz.js || fail "assets/vcp_tz.js must exist"
grep -n 'vcp_tz=' assets/vcp_tz.js >/dev/null \
  || fail "assets/vcp_tz.js must set the vcp_tz cookie"
grep -n 'timeZone' assets/vcp_tz.js >/dev/null \
  || fail "assets/vcp_tz.js must read Intl timeZone"
grep -n 'location.reload' assets/vcp_tz.js >/dev/null \
  || fail "assets/vcp_tz.js must reload once after setting the cookie"
grep -n 'vcp_tz.js\|VCP_TZ_JS' src/app.rs >/dev/null \
  || fail "src/app.rs root layout must include vcp_tz.js"
grep -n 'VCP_TZ_COOKIE' src/tz.rs >/dev/null \
  || fail "src/tz.rs cookie name must stay VCP_TZ_COOKIE"

echo "check_display_tz: OK"
