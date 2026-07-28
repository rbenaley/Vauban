#!/usr/bin/env bash
# Structural invariants for docs search shard surface.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "check_docs_search_shard: $*" >&2
  exit 1
}

SHARD="src/app/org/docs/search_shard.rs"
DOCS="src/app/org/docs.rs"
HELPERS="src/docs_search.rs"

[[ -f "$SHARD" ]] || fail "missing $SHARD"
[[ -f "$HELPERS" ]] || fail "missing $HELPERS"

grep -nE '#\[shard\]' "$SHARD" >/dev/null || fail "$SHARD must define #[shard]"
grep -n 'docs_search_results' "$SHARD" >/dev/null || fail "$SHARD must export docs_search_results"
grep -n 'normalize_org_slug' "$SHARD" >/dev/null || fail "$SHARD must normalize org_slug before require_org"
grep -n 'require_org' "$SHARD" >/dev/null || fail "$SHARD must re-check require_org"
grep -n 'docs_read' "$SHARD" >/dev/null || fail "$SHARD must re-check docs_read"
grep -n 'load_filtered_docs' "$SHARD" >/dev/null || fail "$SHARD must use load_filtered_docs"
grep -n 'DocsFilter::normalized' "$SHARD" >/dev/null || fail "$SHARD must use DocsFilter::normalized"
grep -n 'ctx.org.slug' "$SHARD" >/dev/null || fail "$SHARD must link with authorized ctx.org.slug"
# Shard POSTs are /_topcoat/shards/{id} — path_param::<Org> panics there.
if grep -nE 'path_param' "$SHARD" >/dev/null; then
  fail "$SHARD must not call path_param (no {{org}} on shard routes); use shard org_slug arg"
fi

# Gate order inside the handler body (ignore imports / module docs).
blank_line=$(grep -n 'normalize_org_slug(&org_slug)' "$SHARD" | head -1 | cut -d: -f1)
org_line=$(grep -n 'require_org(cx' "$SHARD" | head -1 | cut -d: -f1)
read_line=$(grep -n 'perms\.docs_read' "$SHARD" | head -1 | cut -d: -f1)
load_line=$(grep -n 'load_filtered_docs(cx' "$SHARD" | head -1 | cut -d: -f1)
[[ -n "$blank_line" && -n "$org_line" && -n "$read_line" && -n "$load_line" ]] \
  || fail "could not locate auth gate markers in $SHARD handler"
if ! [[ "$blank_line" -lt "$org_line" && "$org_line" -lt "$read_line" && "$read_line" -lt "$load_line" ]]; then
  fail "$SHARD gate order must be normalize_org_slug -> require_org -> docs_read -> load_filtered_docs (got $blank_line/$org_line/$read_line/$load_line)"
fi

grep -n 'docs_search_results' "$DOCS" >/dev/null || fail "$DOCS must invoke docs_search_results shard"
grep -n 'org_slug:' "$DOCS" >/dev/null || fail "$DOCS must pass org_slug shard arg"
grep -n 'DocsFilter::normalized\|normalize_query' "$DOCS" >/dev/null \
  || fail "$DOCS must share filter normalization with the shard"
grep -n 'normalize_org_slug' "$HELPERS" >/dev/null || fail "$HELPERS must define normalize_org_slug"
grep -n 'normalize_query' "$HELPERS" >/dev/null || fail "$HELPERS must define normalize_query"

echo "check_docs_search_shard: OK"
