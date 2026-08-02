#!/usr/bin/env bash
# Structural invariants for admin companies search shard surface.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "check_admin_companies_search_shard: $*" >&2
  exit 1
}

SHARD="src/app/admin/companies/search_shard.rs"
PAGE="src/app/admin/companies.rs"
HELPERS="src/companies_search.rs"
LIST_PAGE="src/list_page.rs"

[[ -f "$SHARD" ]] || fail "missing $SHARD"
[[ -f "$HELPERS" ]] || fail "missing $HELPERS"

grep -nE '#\[shard\]' "$SHARD" >/dev/null || fail "$SHARD must define #[shard]"
grep -n 'admin_companies_search_results' "$SHARD" >/dev/null \
  || fail "$SHARD must export admin_companies_search_results"
grep -n 'require_staff' "$SHARD" >/dev/null \
  || fail "$SHARD must re-check require_staff (layout does not run on shard POST)"
grep -n 'companies_manage' "$SHARD" >/dev/null || fail "$SHARD must re-check companies_manage"
grep -n 'COMPANIES_PAGE_SIZE' "$SHARD" >/dev/null \
  || fail "$SHARD must slice with COMPANIES_PAGE_SIZE"
grep -n 'page_slice' "$SHARD" >/dev/null || fail "$SHARD must use page_slice"
grep -n 'data-admin-companies-search-shard' "$SHARD" >/dev/null \
  || fail "$SHARD must mark results container"
grep -n 'company_matches_query' "$SHARD" >/dev/null \
  || fail "$SHARD must use company_matches_query"
if grep -nE 'path_param' "$SHARD" >/dev/null; then
  fail "$SHARD must not call path_param"
fi

staff_line=$(grep -n 'require_staff(cx)' "$SHARD" | head -1 | cut -d: -f1)
manage_line=$(grep -n 'perms\.companies_manage' "$SHARD" | head -1 | cut -d: -f1)
load_line=$(grep -n 'Organization::all' "$SHARD" | head -1 | cut -d: -f1)
[[ -n "$staff_line" && -n "$manage_line" && -n "$load_line" ]] \
  || fail "could not locate auth gate markers in $SHARD handler"
if ! [[ "$staff_line" -lt "$manage_line" && "$manage_line" -lt "$load_line" ]]; then
  fail "$SHARD gate order must be require_staff -> companies_manage -> Organization::all (got $staff_line/$manage_line/$load_line)"
fi

grep -n 'admin_companies_search_results' "$PAGE" >/dev/null \
  || fail "$PAGE must invoke admin_companies_search_results shard"
grep -n 'method="GET"' "$PAGE" >/dev/null || fail "$PAGE search filter form must use method=GET"
grep -n 'type="search"' "$PAGE" >/dev/null || fail "$PAGE must expose type=search"
grep -n 'signal query' "$PAGE" >/dev/null || fail "$PAGE must wire query signal"
grep -n 'page: Option<u32>' "$PAGE" >/dev/null || fail "$PAGE AdminCompaniesQuery must include page"
grep -n 'COMPANIES_PAGE_SIZE' "$PAGE" >/dev/null || fail "$PAGE must use COMPANIES_PAGE_SIZE"
grep -n 'list_toolbar' "$PAGE" >/dev/null || fail "$PAGE must use list_toolbar pager"

grep -n 'fn company_matches_query' "$HELPERS" >/dev/null \
  || fail "$HELPERS must define company_matches_query"
grep -n 'fn normalize_query' "$HELPERS" >/dev/null || fail "$HELPERS must define normalize_query"
grep -n 'COMPANIES_PAGE_SIZE: usize = 3' "$LIST_PAGE" >/dev/null \
  || fail "$LIST_PAGE must define COMPANIES_PAGE_SIZE = 3"

echo "check_admin_companies_search_shard: OK"
