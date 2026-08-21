#!/usr/bin/env bash
# Cursor pagination on full scans (not SSR ?page=N).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "check_toasty_paginate: $*" >&2
  exit 1
}

HELPER=src/toasty_page.rs
[[ -f "$HELPER" ]] || fail "missing $HELPER"
grep -n 'SCAN_PAGE_SIZE' "$HELPER" >/dev/null \
  || fail "$HELPER must define SCAN_PAGE_SIZE"
grep -n 'fn advance_scan_page' "$HELPER" >/dev/null \
  || fail "$HELPER must define advance_scan_page"
grep -n 'page.next' "$HELPER" >/dev/null \
  || fail "$HELPER must walk page.next"

for pair in \
  "src/db.rs:fn resync_release_sort_keys" \
  "src/db.rs:fn ensure_demo_issue_comments" \
  "src/db.rs:fn refresh_thin_doc_bodies" \
  "src/docs_bundle.rs:fn export_articles_to_dir" \
  "src/magic_link.rs:fn purge_expired_tokens" \
  "src/storage/objects.rs:fn delete_org_objects"
do
  file="${pair%%:*}"
  needle="${pair#*:}"
  [[ -f "$file" ]] || fail "missing $file"
  awk -v needle="$needle" '
    $0 ~ needle { hit=1; buf="" }
    hit { buf = buf $0 "\n" }
    hit && /^}/ { print buf; exit }
  ' "$file" | grep -q '\.paginate(' \
    || fail "$file $needle must call .paginate("
  awk -v needle="$needle" '
    $0 ~ needle { hit=1; buf="" }
    hit { buf = buf $0 "\n" }
    hit && /^}/ { print buf; exit }
  ' "$file" | grep -q 'advance_scan_page' \
    || fail "$file $needle must use advance_scan_page"
done

if grep -nE '\.paginate\([^)]*\)[[:space:]]*\.offset\(|\.limit\([^)]*\)[[:space:]]*\.paginate\(' \
  src/db.rs src/docs_bundle.rs src/magic_link.rs src/storage/objects.rs; then
  fail "do not mix .paginate() with .limit() / .offset()"
fi

[[ -f docs/runbooks/toasty_paginate_smoke_test.md ]] \
  || fail "missing docs/runbooks/toasty_paginate_smoke_test.md"

echo "check_toasty_paginate: OK"
