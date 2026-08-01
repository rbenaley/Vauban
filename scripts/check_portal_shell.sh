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

# Topcoat 0.5+: layouts take rendered `slot: Result`, not `Slot<'_>`.
for f in src/app.rs src/app/login.rs src/app/org.rs src/app/admin.rs; do
  grep -E -n 'slot:[[:space:]]*Result' "$f" >/dev/null \
    || fail "$f layout must take slot: Result (Topcoat 0.5+)"
  if grep -n 'Slot<' "$f" >/dev/null || grep -n 'slot.await' "$f" >/dev/null; then
    fail "$f must not use Slot<'_> / slot.await (Topcoat 0.4 API)"
  fi
done

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
grep -n 'require_catalog_assets' src/app.rs >/dev/null \
  || fail "load_assets must require_catalog_assets (stale OUT_DIR bundle guard)"
grep -n 'just bundle' src/app.rs >/dev/null \
  || fail "load_assets panic message must mention just bundle"
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

# UI polish (Concept CSS) — tabular nums, hit areas, motion restraint, press scale.
grep -n 'font-variant-numeric: tabular-nums' "$STYLES" >/dev/null \
  || fail "$STYLES must set tabular-nums for dynamic figures"
grep -A3 '\.vb-ephemeral-countdown' "$STYLES" | grep -q 'tabular-nums' \
  || fail "$STYLES .vb-ephemeral-countdown must use tabular-nums"
grep -A4 '\.vb-stat-value {' "$STYLES" | grep -q 'tabular-nums' \
  || fail "$STYLES .vb-stat-value must use tabular-nums"
if grep -n '\.vb-screen' "$STYLES" | grep -q 'vbIn'; then
  fail "$STYLES .vb-screen must not use vbIn (high-frequency nav)"
fi
grep -A6 '^\.vb-modal {' "$STYLES" | grep -q 'vbIn' \
  || fail "$STYLES .vb-modal must keep vbIn entrance"
grep -n 'scale(0.96)' "$STYLES" >/dev/null \
  || fail "$STYLES must scale a.vb-btn/button.vb-btn to 0.96 on :active"
grep -n 'min-width: 40px' "$STYLES" >/dev/null \
  || fail "$STYLES must set 40px min hit area on compact controls"
grep -A6 'a\.vb-modal-close' "$STYLES" | grep -q 'min-width: 40px' \
  || fail "$STYLES .vb-modal-close must be at least 40px"
grep -A12 '\.vb-ephemeral-revoke' "$STYLES" | grep -q 'min-height: 40px' \
  || fail "$STYLES .vb-ephemeral-revoke must be at least 40px tall"
grep -A12 '\.vb-ephemeral-bar-actions {' "$STYLES" | grep -q 'position: absolute' \
  || fail "$STYLES .vb-ephemeral-bar-actions must be absolute so bar matches verify"
grep -A10 '\.vb-ephemeral-bar {' "$STYLES" | grep -q 'min-height:' \
  || fail "$STYLES .vb-ephemeral-bar must pin a shared min-height for verify/ephemeral"
grep -A8 '\.vb-ephemeral-title {' "$STYLES" | grep -q 'letter-spacing: 0.04em' \
  || fail "$STYLES .vb-ephemeral-title must pin letter-spacing with countdown"
grep -A8 '\.vb-ephemeral-cmd-head {' "$STYLES" | grep -q 'min-height: 28px' \
  || fail "$STYLES .vb-ephemeral-cmd-head must reserve seg height for verify align"
grep -n 'antialiased' "$STYLES" >/dev/null \
  || fail "$STYLES body must enable -webkit-font-smoothing: antialiased"
grep -n 'text-wrap: balance' "$STYLES" >/dev/null \
  || fail "$STYLES titles must use text-wrap: balance"
grep -n 'text-wrap: pretty' "$STYLES" >/dev/null \
  || fail "$STYLES leads/body must use text-wrap: pretty"
grep -n '\.vb-eph-seg' "$STYLES" | head -1 >/dev/null
grep -A2 '\.vb-eph-seg {' "$STYLES" | grep -q 'border-radius: 6px' \
  || fail "$STYLES .vb-eph-seg outer radius must be 6px (4+2 concentric)"

ICONS="src/app/_components/icons.rs"
grep -n 'RAIL_STROKE' "$ICONS" >/dev/null || fail "$ICONS must define RAIL_STROKE"
grep -n 'CONTROL_STROKE' "$ICONS" >/dev/null || fail "$ICONS must define CONTROL_STROKE"
grep -n 'pub const RAIL_STROKE: &str = "1.6"' "$ICONS" >/dev/null \
  || fail "$ICONS RAIL_STROKE must be 1.6"
grep -n 'pub const CONTROL_STROKE: &str = "1.8"' "$ICONS" >/dev/null \
  || fail "$ICONS CONTROL_STROKE must be 1.8"
# ico_home / ico_issues must be stroke outlines (not fill="currentColor" SVGs).
if awk '
  /pub async fn ico_home/ { in_fn=1; next }
  in_fn && /pub async fn / { exit }
  in_fn && /fill="currentColor"/ { bad=1; exit }
  END { exit !bad }
' "$ICONS"; then
  fail "$ICONS ico_home must not use fill=\"currentColor\""
fi
if awk '
  /pub async fn ico_issues/ { in_fn=1; next }
  in_fn && /pub async fn / { exit }
  in_fn && /fill="currentColor"/ { bad=1; exit }
  END { exit !bad }
' "$ICONS"; then
  fail "$ICONS ico_issues must not use fill=\"currentColor\""
fi

echo "check_portal_shell: OK"
