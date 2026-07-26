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
grep -n 'show_admin: perms.admin_view' src/app/org.rs >/dev/null \
  || fail "org_layout must gate admin rail via perms.admin_view"
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

grep -n 'fn nav_from_path' src/nav.rs >/dev/null \
  || fail "src/nav.rs must expose nav_from_path for unit/proptest"
grep -n 'fn nav_from_cx' src/nav.rs >/dev/null \
  || fail "src/nav.rs must expose nav_from_cx"

echo "check_portal_shell: OK"
