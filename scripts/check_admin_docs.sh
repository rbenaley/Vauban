#!/usr/bin/env bash
# Structural invariants for admin documentation editor surface.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "check_admin_docs: $*" >&2
  exit 1
}

NEW="src/app/org/admin/docs/new.rs"
DOC="src/app/org/admin/docs/doc.rs"
LIST="src/app/org/admin/docs.rs"
CLIENT="src/app/org/docs.rs"
CLIENT_DOC="src/app/org/docs/doc.rs"

[[ -f "$NEW" ]] || fail "missing $NEW"
[[ -f "$DOC" ]] || fail "missing $DOC"

grep -n 'method="POST"' "$NEW" >/dev/null || fail "$NEW must POST compose form"
grep -nE '#\[route\(POST' "$NEW" >/dev/null || fail "$NEW must define POST create route"
grep -n 'docs_write' "$NEW" >/dev/null || fail "$NEW must gate on docs_write"

grep -nE '#\[route\(POST' "$DOC" >/dev/null || fail "$DOC must define POST update/publish routes"
grep -n '/publish' "$DOC" >/dev/null || fail "$DOC must expose publish route"
grep -n '/unpublish' "$DOC" >/dev/null || fail "$DOC must expose unpublish route"
grep -n 'docs_write' "$DOC" >/dev/null || fail "$DOC must gate on docs_write"
grep -n 'docs_write' "$LIST" >/dev/null || fail "$LIST must gate on docs_write"

# Client list must filter PUBLISHED at the Toasty query (not all() alone).
grep -n 'DOC_STATUS_PUBLISHED' "$CLIENT" >/dev/null \
  || fail "$CLIENT must filter DOC_STATUS_PUBLISHED"
grep -n 'fields().status()' "$CLIENT" >/dev/null \
  || fail "$CLIENT load_filtered_docs must filter via fields().status()"
grep -n 'DOC_STATUS_PUBLISHED' "$CLIENT_DOC" >/dev/null \
  || fail "$CLIENT_DOC must require PUBLISHED status"

echo "check_admin_docs: OK"
