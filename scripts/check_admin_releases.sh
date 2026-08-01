#!/usr/bin/env bash
# Structural invariants for admin release manager surface.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "check_admin_releases: $*" >&2
  exit 1
}

NEW="src/app/admin/releases/new.rs"
LIST="src/app/admin/releases.rs"

[[ -f "$NEW" ]] || fail "missing $NEW"

grep -n 'method="POST"' "$NEW" >/dev/null || fail "$NEW must POST compose form"
grep -nE '#\[route\(POST' "$NEW" >/dev/null || fail "$NEW must define POST create route"
grep -n 'releases_manage' "$NEW" >/dev/null || fail "$NEW must gate on releases_manage"
grep -n 'toasty::create!(Release' "$NEW" >/dev/null || fail "$NEW must create Release rows"
grep -n 'method="GET"' "$NEW" >/dev/null && fail "$NEW must not use method=GET on compose form"
if grep -nE 'max-width:\s*(720|820)px' "$NEW" >/dev/null 2>&1; then
  fail "$NEW must not constrain content width (Concept full width)"
fi

if [[ -f "$LIST" ]]; then
  grep -n 'releases_manage\|admin_view' "$LIST" >/dev/null \
    || fail "$LIST must gate on releases_manage / admin_view"
  # SSR list pagination (shared list_page + toolbar pager).
  grep -nE 'LIST_PAGE_SIZE' "$LIST" >/dev/null \
    || fail "$LIST must use LIST_PAGE_SIZE"
  grep -n 'list_toolbar' "$LIST" >/dev/null \
    || fail "$LIST must use list_toolbar for pager"
  grep -n 'page: Option<u32>' "$LIST" >/dev/null \
    || fail "$LIST AdminReleasesQuery must include page: Option<u32>"
  grep -n 'page_slice' "$LIST" >/dev/null \
    || fail "$LIST must slice rows with page_slice"
  grep -n 'channel_badge_class' "$LIST" >/dev/null \
    || fail "$LIST must color channel badges via channel_badge_class"
  if grep -n 'vb-badge soft' "$LIST" | grep -q 'rel.channel'; then
    fail "$LIST must not hardcode vb-badge soft on rel.channel"
  fi
fi

echo "check_admin_releases: OK"
