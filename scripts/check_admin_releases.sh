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

if [[ -f "$LIST" ]]; then
  grep -n 'releases_manage\|admin_view' "$LIST" >/dev/null \
    || fail "$LIST must gate on releases_manage / admin_view"
fi

echo "check_admin_releases: OK"
