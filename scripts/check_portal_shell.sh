#!/usr/bin/env bash
# Structural invariants for portal shell chrome (Topcoat layouts + rail/topbar/nav).
# Uses grep so CI works without ripgrep on PATH.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "check_portal_shell: $*" >&2
  exit 1
}

# Layouts must be Topcoat #[layout] modules — not a legacy layout.rs shell.
if [[ -f src/layout.rs ]]; then
  fail "src/layout.rs must not exist (use Topcoat #[layout] modules)"
fi
if grep -rn 'layout::shell' src/app --include='*.rs' >/dev/null 2>&1; then
  fail "must not call layout::shell"
fi

grep -n '#\[layout\]' src/app.rs >/dev/null \
  || fail "src/app.rs must define root #[layout]"
grep -n '#\[layout\]' src/app/login.rs >/dev/null \
  || fail "src/app/login.rs must define login #[layout]"
grep -n '#\[layout\]' src/app/org.rs >/dev/null \
  || fail "src/app/org.rs must define org #[layout]"

grep -n 'vb_rail' src/app/org.rs >/dev/null \
  || fail "org_layout must render vb_rail"
grep -n 'vb_topbar' src/app/org.rs >/dev/null \
  || fail "org_layout must render vb_topbar"
grep -n 'admin_view' src/app/_components/rail.rs >/dev/null \
  || fail "vb_rail must gate ADMIN block via perms.admin_view"
grep -n 'require_org' src/app/_components/rail.rs >/dev/null \
  || fail "vb_rail must resolve org via require_org"
grep -n 'nav_from_cx' src/app/org.rs >/dev/null \
  || fail "org_layout must derive nav via nav_from_cx"
grep -n 'vb-shell' src/app/org.rs >/dev/null \
  || fail "org_layout must use vb-shell chrome"

grep -n 'vb-login-body' src/app/login.rs >/dev/null \
  || fail "login_layout must use vb-login-body"

grep -n 'runtime::script' src/app.rs >/dev/null \
  || fail "root_layout must include topcoat::runtime::script"
grep -n 'stylesheet!' src/app.rs >/dev/null \
  || fail "root_layout must include tailwind stylesheet!"
grep -n 'rel="icon"' src/app.rs >/dev/null \
  || fail "root_layout must link a favicon"
grep -n 'apple-touch-icon' src/app.rs >/dev/null \
  || fail "root_layout must link apple-touch-icon"
grep -n 'GET "/favicon.ico"' src/app.rs >/dev/null \
  || fail "must serve /favicon.ico (browser probe)"
grep -n 'GET "/apple-touch-icon.png"' src/app.rs >/dev/null \
  || fail "must serve /apple-touch-icon.png (browser probe)"
grep -n 'GET "/apple-touch-icon-precomposed.png"' src/app.rs >/dev/null \
  || fail "must serve /apple-touch-icon-precomposed.png (browser probe)"
test -f assets/favicon.svg \
  || fail "assets/favicon.svg must exist (SVG brand mark)"
test -f assets/favicon.ico \
  || fail "assets/favicon.ico must exist for /favicon.ico"
test -f assets/apple-touch-icon.png \
  || fail "assets/apple-touch-icon.png must exist"
test -f assets/apple-touch-icon-precomposed.png \
  || fail "assets/apple-touch-icon-precomposed.png must exist"
test -f assets/favicon-16x16.png -a -f assets/favicon-32x32.png \
  || fail "assets/favicon-16x16.png and favicon-32x32.png must exist"

grep -n 'fn nav_from_path' src/nav.rs >/dev/null \
  || fail "src/nav.rs must expose nav_from_path for unit/proptest"
grep -n 'fn nav_from_cx' src/nav.rs >/dev/null \
  || fail "src/nav.rs must expose nav_from_cx"

echo "check_portal_shell: OK"
