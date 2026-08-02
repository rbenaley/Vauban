#!/usr/bin/env bash
# Structural invariants for Toasty filtered queries (docs / builds / seats /
# list loaders / hot-path lookup bans).
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
SEATS="src/seats.rs"
COMPANIES_LOAD="src/app/admin/companies/load.rs"
COMPANIES_SYNC="src/companies_accounts.rs"
ORG_ISSUES="src/app/org/issues.rs"
ADMIN_ISSUES_SHARD="src/app/admin/issues/search_shard.rs"
ADMIN_DOCS="src/app/admin/docs.rs"
ORG_DASH="src/app/org.rs"

[[ -f "$DOCS" ]] || fail "missing $DOCS"

# Client docs must filter status at the DB layer (shared docs_filtered_query!).
grep -n 'fn load_filtered_docs_page' "$DOCS" >/dev/null \
  || fail "$DOCS must define load_filtered_docs_page"
grep -n 'macro_rules! docs_filtered_query' "$DOCS" >/dev/null \
  || fail "$DOCS must define docs_filtered_query for shared SQL filters"
grep -n 'fields().status()' "$DOCS" >/dev/null \
  || fail "$DOCS must filter via fields().status()"
grep -n 'DOC_STATUS_PUBLISHED' "$DOCS" >/dev/null \
  || fail "$DOCS must reference DOC_STATUS_PUBLISHED"
grep -n 'ilike_with_escape\|\.ilike(' "$DOCS" >/dev/null \
  || fail "$DOCS must use ilike for search"
grep -n '\.limit(' "$DOCS" >/dev/null \
  || fail "$DOCS must page with .limit("
grep -n '\.offset(' "$DOCS" >/dev/null \
  || fail "$DOCS must page with .offset("
grep -n '\.count()' "$DOCS" >/dev/null \
  || fail "$DOCS must use .count() for pager totals"

# Detail must include deferred body.
grep -n 'include(DocArticle::fields().body())' "$DOC_DETAIL" >/dev/null \
  || fail "$DOC_DETAIL must .include(body) for deferred body"

# Builds channel + SQL tenant net (org-scoped loader).
grep -n 'fn load_releases_for_org' "$BUILDS" >/dev/null \
  || fail "$BUILDS must define load_releases_for_org"
grep -n 'fields().channel()' "$BUILDS" >/dev/null \
  || fail "$BUILDS load_releases_for_org must filter via fields().channel()"
grep -n 'organization_id().in_list\|in_list(\[RELEASE_GA_ORG_ID' "$BUILDS" >/dev/null \
  || fail "$BUILDS load_releases_for_org must filter organization_id via in_list"
grep -n 'RELEASE_STATUS_PUBLISHED' "$BUILDS" >/dev/null \
  || fail "$BUILDS must filter RELEASE_STATUS_PUBLISHED in SQL"
grep -n 'fn find_visible_release_by_version' "$BUILDS" >/dev/null \
  || fail "$BUILDS must define find_visible_release_by_version"

# Seats: SQL COUNT(*), never rows.len() after full membership exec.
grep -n '\.count()' "$SEATS" >/dev/null \
  || fail "$SEATS membership_count must use .count()"
if grep -n 'rows\.len()' "$SEATS" >/dev/null; then
  fail "$SEATS must not count memberships via rows.len() after exec"
fi

# Org issues list: SQL limit/offset/count + ilike search.
grep -n '\.limit(' "$ORG_ISSUES" >/dev/null \
  || fail "$ORG_ISSUES must page with .limit("
grep -n '\.offset(' "$ORG_ISSUES" >/dev/null \
  || fail "$ORG_ISSUES must page with .offset("
grep -n '\.count()' "$ORG_ISSUES" >/dev/null \
  || fail "$ORG_ISSUES must use .count() for pager totals"
grep -n 'ilike_with_escape\|\.ilike(' "$ORG_ISSUES" >/dev/null \
  || fail "$ORG_ISSUES must use ilike for search"

# Admin issues shard: no naked Issue::all().exec without filters nearby.
grep -n 'organization_id\|ilike_with_escape\|\.ilike(' "$ADMIN_ISSUES_SHARD" >/dev/null \
  || fail "$ADMIN_ISSUES_SHARD must filter tenant and/or search in SQL"

# Admin docs list: SQL paging.
grep -n '\.limit(' "$ADMIN_DOCS" >/dev/null \
  || fail "$ADMIN_DOCS must page with .limit("
grep -n '\.offset(' "$ADMIN_DOCS" >/dev/null \
  || fail "$ADMIN_DOCS must page with .offset("
grep -n '\.count()' "$ADMIN_DOCS" >/dev/null \
  || fail "$ADMIN_DOCS must use .count() for pager totals"

# Companies: two-phase search + page hydration via in_list; no User::all().exec naked.
grep -n 'ilike_with_escape' "$COMPANIES_LOAD" >/dev/null \
  || fail "$COMPANIES_LOAD must use ilike_with_escape for search"
grep -n '\.limit(' "$COMPANIES_LOAD" >/dev/null \
  || fail "$COMPANIES_LOAD must page with .limit("
grep -n '\.offset(' "$COMPANIES_LOAD" >/dev/null \
  || fail "$COMPANIES_LOAD must page with .offset("
grep -n 'in_list' "$COMPANIES_LOAD" >/dev/null \
  || fail "$COMPANIES_LOAD must hydrate via in_list"
if grep -nE 'User::all\(\)[[:space:]]*\.[[:space:]]*exec' "$COMPANIES_LOAD" >/dev/null; then
  fail "$COMPANIES_LOAD must not call User::all().exec without filters"
fi
if grep -nE 'User::all\(\)[[:space:]]*\.[[:space:]]*exec' "$COMPANIES_SYNC" >/dev/null; then
  fail "$COMPANIES_SYNC must not call User::all().exec without filters"
fi
grep -n 'users_by_ids\|email().in_list\|id().in_list' "$COMPANIES_SYNC" >/dev/null \
  || fail "$COMPANIES_SYNC must look up users via in_list / users_by_ids"

# Dashboard: one org-scoped issues load + Rust stats; docs COUNT; releases loader.
grep -n 'load_releases_for_org' "$ORG_DASH" >/dev/null \
  || fail "$ORG_DASH must load releases via load_releases_for_org"
grep -n 'summarize_issue_stats\|DASHBOARD_ISSUES_CAP' "$ORG_DASH" >/dev/null \
  || fail "$ORG_DASH must summarize issues via dashboard_stats (not multi COUNT)"
grep -n 'organization_id().eq' "$ORG_DASH" >/dev/null \
  || fail "$ORG_DASH must filter issues by organization_id"
# Docs tile still uses SQL COUNT(*); issue tiles must not multi-count.
issue_count_hits=$(grep -c 'Issue::all()' "$ORG_DASH" || true)
if [[ "$issue_count_hits" -gt 1 ]]; then
  fail "$ORG_DASH must load Issue::all() at most once for dashboard stats"
fi
grep -n 'DocArticle::all()' "$ORG_DASH" >/dev/null \
  || fail "$ORG_DASH must still load DocArticle for docs tile"
grep -n '\.count()' "$ORG_DASH" >/dev/null \
  || fail "$ORG_DASH must use .count() for published docs counter"

# Guard against unfiltered DocArticle::all() as the primary list path without status.
if grep -n 'DocArticle::all()' "$DOCS" >/dev/null; then
  if ! grep -nE 'DocArticle::all\(\)[[:space:]]*\.[[:space:]]*filter\(DocArticle::fields\(\)\.status\(\)' "$DOCS" >/dev/null \
     && ! awk '
          /DocArticle::all\(\)/ { line=NR }
          /fields\(\)\.status\(\)/ && line && NR<=line+3 { ok=1 }
          END { exit !ok }
        ' "$DOCS"; then
    fail "$DOCS must not call DocArticle::all() without a status filter in load_filtered_docs_page"
  fi
fi

# Hot-path bans: naked User::all().exec / Organization::all().exec outside allowlist.
# Allow: db seed, id_lookups (always filtered), auth membership helpers, login email lookup.
forbid_naked_all_exec() {
  local file="$1"
  local label="$2"
  if grep -nE '(User|Organization)::all\(\)[[:space:]]*\.[[:space:]]*exec' "$file" >/dev/null 2>&1; then
    fail "$label ($file) must not call User/Organization::all().exec without a filter chain"
  fi
}

forbid_naked_all_exec "src/app/admin/companies.rs" "admin companies page"
forbid_naked_all_exec "src/app/admin/companies/search_shard.rs" "companies search shard"
forbid_naked_all_exec "src/app/org/issues/search_shard.rs" "org issues search shard"
forbid_naked_all_exec "src/app/org/docs/search_shard.rs" "org docs search shard"

echo "check_toasty_filters: OK"
