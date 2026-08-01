#!/usr/bin/env bash
# Structural invariants for admin issues search shard surface.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "check_admin_issues_search_shard: $*" >&2
  exit 1
}

SHARD="src/app/admin/issues/search_shard.rs"
PAGE="src/app/admin/issues.rs"
HELPERS="src/issues_search.rs"

[[ -f "$SHARD" ]] || fail "missing $SHARD"
[[ -f "$HELPERS" ]] || fail "missing $HELPERS"

grep -nE '#\[shard\]' "$SHARD" >/dev/null || fail "$SHARD must define #[shard]"
grep -n 'admin_issues_search_results' "$SHARD" >/dev/null || fail "$SHARD must export admin_issues_search_results"
grep -n 'require_staff' "$SHARD" >/dev/null || fail "$SHARD must re-check require_staff (layout does not run on shard POST)"
grep -n 'issues_read' "$SHARD" >/dev/null || fail "$SHARD must re-check issues_read"
grep -n 'resolve_org_filter' "$SHARD" >/dev/null || fail "$SHARD must use resolve_org_filter"
grep -n 'data-admin-issues-search-shard' "$SHARD" >/dev/null || fail "$SHARD must mark results container"
if grep -nE 'path_param' "$SHARD" >/dev/null; then
  fail "$SHARD must not call path_param"
fi

staff_line=$(grep -n 'require_staff(cx)' "$SHARD" | head -1 | cut -d: -f1)
read_line=$(grep -n 'perms\.issues_read' "$SHARD" | head -1 | cut -d: -f1)
load_line=$(grep -n 'Issue::all' "$SHARD" | head -1 | cut -d: -f1)
[[ -n "$staff_line" && -n "$read_line" && -n "$load_line" ]] \
  || fail "could not locate auth gate markers in $SHARD handler"
if ! [[ "$staff_line" -lt "$read_line" && "$read_line" -lt "$load_line" ]]; then
  fail "$SHARD gate order must be require_staff -> issues_read -> Issue::all (got $staff_line/$read_line/$load_line)"
fi

grep -n 'admin_issues_search_results' "$PAGE" >/dev/null || fail "$PAGE must invoke admin_issues_search_results shard"
grep -n 'org_query' "$PAGE" >/dev/null || fail "$PAGE must wire org_query signal"
# Progressive-enhancement filter form (not a mutation) — keep GET for ?q= / ?org=.
grep -n 'method="GET"' "$PAGE" >/dev/null || fail "$PAGE search filter form must use method=GET"
grep -n 'page: Option<u32>' "$PAGE" >/dev/null || fail "$PAGE AdminIssuesQuery must include page: Option<u32>"
grep -n 'filter_row' "$PAGE" >/dev/null || fail "$PAGE must use filter_row for chips + pager"
grep -n 'page_slice\|LIST_PAGE_SIZE' "$SHARD" >/dev/null \
  || fail "$SHARD must slice results with page_slice / LIST_PAGE_SIZE"
grep -n 'resolve_org_filter' "$HELPERS" >/dev/null || fail "$HELPERS must define resolve_org_filter"

echo "check_admin_issues_search_shard: OK"
