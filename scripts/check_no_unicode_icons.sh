#!/usr/bin/env bash
# Structural invariant: portal UI chrome must use SVG icons, not Unicode glyphs.
# Typographic punctuation (en-dash, ellipsis in copy) is out of scope.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "check_no_unicode_icons: $*" >&2
  exit 1
}

# Decorative / control glyphs formerly used as icons in view! markup and CSS.
PATTERN='[→←↑↓✓✕＋✎⌂⚑▾▸⧖▪📎★☆]'

hits="$(
  {
    grep -rnE --include='*.rs' "$PATTERN" src/app || true
    grep -nE "$PATTERN" styles.css || true
  } | grep -vE '^\s*$' || true
)"

if [[ -n "$hits" ]]; then
  echo "$hits" >&2
  fail "Unicode icon glyphs found; use SVG helpers in src/app/_components/icons.rs (or CSS mask) instead"
fi

# Shared icon module must exist and export the core set.
test -f src/app/_components/icons.rs \
  || fail "src/app/_components/icons.rs must exist"
grep -n 'pub async fn ico_home' src/app/_components/icons.rs >/dev/null \
  || fail "icons.rs must export ico_home"
grep -n 'pub async fn ico_close' src/app/_components/icons.rs >/dev/null \
  || fail "icons.rs must export ico_close"
grep -n 'ico_home(cx, 17)' src/app/_components/rail.rs >/dev/null \
  || fail "vb_rail must use shared ico_home SVG"
grep -n 'ico_close' src/app/_components/modal.rs >/dev/null \
  || fail "modal close control must use ico_close SVG"
grep -n 'vb-link::after' styles.css >/dev/null \
  || fail "styles.css must paint vb-link arrows via SVG mask (::after)"
grep -n 'vb-back::before' styles.css >/dev/null \
  || fail "styles.css must paint vb-back arrows via SVG mask (::before)"
awk '
  /\.vb-modal-body li::before/ { in_block=1 }
  in_block && /content:[[:space:]]*"[^"]+"/ {
    if ($0 !~ /content:[[:space:]]*""/) { bad=1 }
  }
  in_block && /}/ { in_block=0 }
  END { exit bad }
' styles.css || fail "modal list bullets must use empty content (CSS square), not Unicode"

echo "check_no_unicode_icons: OK"
