#!/usr/bin/env bash
# Structural invariants for org issues search shard surface.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "check_org_issues_search_shard: $*" >&2
  exit 1
}

SHARD="src/app/org/issues/search_shard.rs"
PAGE="src/app/org/issues.rs"
HELPERS="src/issues_search.rs"

[[ -f "$SHARD" ]] || fail "missing $SHARD"
[[ -f "$HELPERS" ]] || fail "missing $HELPERS"

grep -nE '#\[shard\]' "$SHARD" >/dev/null || fail "$SHARD must define #[shard]"
grep -n 'issues_search_results' "$SHARD" >/dev/null || fail "$SHARD must export issues_search_results"
grep -n 'normalize_org_slug' "$SHARD" >/dev/null || fail "$SHARD must normalize org_slug before require_org"
grep -n 'require_org' "$SHARD" >/dev/null || fail "$SHARD must re-check require_org"
grep -n 'issues_read' "$SHARD" >/dev/null || fail "$SHARD must re-check issues_read"
grep -n 'ctx.org.slug' "$SHARD" >/dev/null || fail "$SHARD must link with authorized ctx.org.slug"
grep -n 'data-issues-search-shard' "$SHARD" >/dev/null || fail "$SHARD must mark results container"
if grep -nE 'path_param' "$SHARD" >/dev/null; then
  fail "$SHARD must not call path_param (no {{org}} on shard routes); use shard org_slug arg"
fi

blank_line=$(grep -n 'normalize_org_slug(&org_slug)' "$SHARD" | head -1 | cut -d: -f1)
org_line=$(grep -n 'require_org(cx' "$SHARD" | head -1 | cut -d: -f1)
read_line=$(grep -n 'perms\.issues_read' "$SHARD" | head -1 | cut -d: -f1)
load_line=$(grep -n 'Issue::all' "$SHARD" | head -1 | cut -d: -f1)
[[ -n "$blank_line" && -n "$org_line" && -n "$read_line" && -n "$load_line" ]] \
  || fail "could not locate auth gate markers in $SHARD handler"
if ! [[ "$blank_line" -lt "$org_line" && "$org_line" -lt "$read_line" && "$read_line" -lt "$load_line" ]]; then
  fail "$SHARD gate order must be normalize_org_slug -> require_org -> issues_read -> Issue::all (got $blank_line/$org_line/$read_line/$load_line)"
fi

grep -n 'issues_search_results' "$PAGE" >/dev/null || fail "$PAGE must invoke issues_search_results shard"
grep -n 'org_slug:' "$PAGE" >/dev/null || fail "$PAGE must pass org_slug shard arg"
grep -n 'normalize_query' "$HELPERS" >/dev/null || fail "$HELPERS must define normalize_query"
grep -n 'issue_matches_query' "$HELPERS" >/dev/null || fail "$HELPERS must define issue_matches_query"

echo "check_org_issues_search_shard: OK"
