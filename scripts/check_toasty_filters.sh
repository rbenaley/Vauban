#!/usr/bin/env bash
# Structural invariants for Toasty filtered queries (docs / builds).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "check_toasty_filters: $*" >&2
  exit 1
}

DOCS="src/app/org/docs.rs"
DOC_DETAIL="src/app/org/docs/doc.rs"
BUILDS="src/app/org/builds.rs"

[[ -f "$DOCS" ]] || fail "missing $DOCS"

# Client docs must filter status at the DB layer inside load_filtered_docs.
if ! awk '
  /fn load_filtered_docs/ { in_fn=1 }
  in_fn && /fields\(\)\.status\(\)/ { found=1 }
  in_fn && /^}/ { exit }
  END { exit !found }
' "$DOCS"; then
  fail "$DOCS load_filtered_docs must filter via fields().status()"
fi

grep -n 'DOC_STATUS_PUBLISHED' "$DOCS" >/dev/null \
  || fail "$DOCS must reference DOC_STATUS_PUBLISHED"

# Detail must include deferred body.
grep -n 'include(DocArticle::fields().body())' "$DOC_DETAIL" >/dev/null \
  || fail "$DOC_DETAIL must .include(body) for deferred body"

# Builds channel filter via Toasty fields.
grep -n 'fn load_releases' "$BUILDS" >/dev/null || fail "$BUILDS must define load_releases"
grep -n 'fields().channel()' "$BUILDS" >/dev/null \
  || fail "$BUILDS load_releases must filter via fields().channel()"

# Guard against unfiltered DocArticle::all() as the primary list path without status.
if grep -n 'DocArticle::all()' "$DOCS" >/dev/null; then
  # Allowed only when chained with status filter in the same expression / nearby.
  if ! grep -nE 'DocArticle::all\(\)[[:space:]]*\.[[:space:]]*filter\(DocArticle::fields\(\)\.status\(\)' "$DOCS" >/dev/null \
     && ! awk '
          /DocArticle::all\(\)/ { line=NR }
          /fields\(\)\.status\(\)/ && line && NR<=line+3 { ok=1 }
          END { exit !ok }
        ' "$DOCS"; then
    fail "$DOCS must not call DocArticle::all() without a status filter in load_filtered_docs"
  fi
fi

echo "check_toasty_filters: OK"
