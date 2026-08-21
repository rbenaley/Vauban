#!/usr/bin/env bash
# Structural invariants: list page + embedded shard share memoized domain loaders.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "check_request_sql_dedup: $*" >&2
  exit 1
}

pin_memo() {
  local file="$1"
  local fn="$2"
  grep -nE '#\[memoize' "$file" >/dev/null \
    || fail "$file must use #[memoize]"
  awk -v fn="$fn" '
    /#\[memoize/ { memo=1; next }
    memo && $0 ~ ("fn " fn) { found=1; exit }
    /^[[:space:]]*(pub )?async fn |^[[:space:]]*fn / && memo && $0 !~ fn { memo=0 }
    END { exit !found }
  ' "$file" || fail "$file must #[memoize] $fn"
}

DOCS="src/app/org/docs.rs"
ISSUES="src/app/org/issues.rs"
ADMIN_ISSUES="src/app/admin/issues/search_shard.rs"
COMPANIES_LOAD="src/app/admin/companies/load.rs"
COMPANIES_PAGE="src/app/admin/companies.rs"
COMPANIES_SHARD="src/app/admin/companies/search_shard.rs"

pin_memo "$DOCS" "count_filtered_docs_memo"
grep -n 'count_filtered_docs_memo' "$DOCS" >/dev/null \
  || fail "$DOCS count_filtered_docs must call count_filtered_docs_memo"
grep -n 'count_filtered_docs' "$DOCS" >/dev/null \
  || fail "$DOCS load_filtered_docs_page must go through count_filtered_docs"

pin_memo "$ISSUES" "count_filtered_issues_memo"
grep -n 'count_filtered_issues_memo' "$ISSUES" >/dev/null \
  || fail "$ISSUES count_filtered_issues must call count_filtered_issues_memo"

pin_memo "$ADMIN_ISSUES" "resolve_org_id_memo"
pin_memo "$ADMIN_ISSUES" "count_admin_filtered_issues_memo"
grep -n 'count_admin_filtered_issues_memo\|count_admin_filtered_issues' "$ADMIN_ISSUES" >/dev/null \
  || fail "$ADMIN_ISSUES must use memoized admin issue count"

pin_memo "$COMPANIES_LOAD" "company_cards_page_memo"
grep -n 'company_cards_page' "$COMPANIES_PAGE" >/dev/null \
  || fail "$COMPANIES_PAGE must call company_cards_page"
grep -n 'company_cards_page' "$COMPANIES_SHARD" >/dev/null \
  || fail "$COMPANIES_SHARD must call company_cards_page"
if grep -nE 'load_company_cards_page\(' "$COMPANIES_PAGE" >/dev/null; then
  fail "$COMPANIES_PAGE must not call load_company_cards_page directly (use company_cards_page)"
fi
if grep -nE 'load_company_cards_page\(' "$COMPANIES_SHARD" >/dev/null; then
  fail "$COMPANIES_SHARD must not call load_company_cards_page directly (use company_cards_page)"
fi

echo "check_request_sql_dedup: OK"
