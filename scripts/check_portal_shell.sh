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
grep -n '#\[layout\]' src/app/admin.rs >/dev/null \
  || fail "src/app/admin.rs must define admin #[layout]"

grep -n 'vb_rail' src/app/org.rs >/dev/null \
  || fail "org_layout must render vb_rail"
grep -n 'vb_topbar' src/app/org.rs >/dev/null \
  || fail "org_layout must render vb_topbar"
grep -n 'vb_rail' src/app/admin.rs >/dev/null \
  || fail "admin_layout must render vb_rail"
grep -n 'require_staff' src/app/admin.rs >/dev/null \
  || fail "admin_layout must call require_staff"
grep -n '/admin/issues' src/app/_components/rail.rs >/dev/null \
  || fail "vb_rail admin Issues must link /admin/issues"
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
# Well-known probes: fixed paths via include_bytes!; layout links stay on asset!.
grep -n 'include_bytes!' src/app.rs >/dev/null \
  || fail "icon probes must embed bytes with include_bytes!"
grep -n 'fn static_icon_response' src/app.rs >/dev/null \
  || fail "icon probes must use static_icon_response"
grep -n 'asset!("assets/favicon.svg")' src/app.rs >/dev/null \
  || fail "layout favicon links must use asset! (hashed)"
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

STYLES="styles.css"
grep -n 'a.vb-rail-item.active' "$STYLES" >/dev/null \
  || fail "$STYLES must style a.vb-rail-item.active"
grep -n 'a.vb-rail-item .lbl' "$STYLES" >/dev/null \
  || fail "$STYLES must style rail labels (.lbl) in mono separately from icons"
grep -n 'a.vb-rail-item .vb-ico svg' "$STYLES" >/dev/null \
  || fail "$STYLES must size rail icon SVGs (.vb-ico)"
grep -n 'ico_home(cx, 17)' src/app/_components/rail.rs >/dev/null \
  || fail "vb_rail must use shared SVG rail icons (ico_home)"
bash scripts/check_no_unicode_icons.sh

grep -n 'color-mix(in srgb, var(--accent) 26%, #14171c)' "$STYLES" >/dev/null \
  || fail "$STYLES active rail bg must use accent mix on #14171c"
grep -n 'color-mix(in srgb, var(--accent) 58%, #fff)' "$STYLES" >/dev/null \
  || fail "$STYLES active rail color must use accent mix on #fff"
grep -n -- '--rail-idle: #6b7280' "$STYLES" >/dev/null \
  || fail "$STYLES --rail-idle must be #6b7280"
if awk '
  /a\.vb-rail-item\.active/ { in_block=1 }
  in_block && /background:[[:space:]]*var\(--accent\)/ { found=1 }
  in_block && /}/ { in_block=0 }
  END { exit !found }
' "$STYLES"; then
  fail "$STYLES must not use solid accent fill on active rail items"
fi

echo "check_portal_shell: OK"
