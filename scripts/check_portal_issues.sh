#!/usr/bin/env bash
# Structural invariants for portal issue tracker surface.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "check_portal_issues: $*" >&2
  exit 1
}

LIST="src/app/org/issues.rs"
NEW="src/app/org/issues/new.rs"
DETAIL="src/app/org/issues/issue_key.rs"

[[ -f "$LIST" ]] || fail "missing $LIST"
[[ -f "$NEW" ]] || fail "missing $NEW"
[[ -f "$DETAIL" ]] || fail "missing $DETAIL"

grep -nE '#\[route\(POST' "$LIST" >/dev/null || fail "$LIST must define POST report_issue"
grep -n 'details' "$LIST" >/dev/null || fail "$LIST must persist form details"
grep -n 'issues_write' "$LIST" >/dev/null || fail "$LIST must gate writes on issues_write"
grep -n 'organization_id' "$LIST" >/dev/null || fail "$LIST must scope issues by organization_id"
# Light SSR pagination pin (full pyramid lives on org_issues_search_shard).
grep -n 'page: Option<u32>' "$LIST" >/dev/null || fail "$LIST IssuesQuery must include page: Option<u32>"
grep -n 'filter_row' "$LIST" >/dev/null || fail "$LIST must use filter_row for chips + pager"

grep -n 'method="POST"' "$NEW" >/dev/null || fail "$NEW must POST report form"
grep -n 'name="details"' "$NEW" >/dev/null || fail "$NEW must include details field"

grep -n 'issue.details' "$DETAIL" >/dev/null || fail "$DETAIL must render issue.details"
grep -n 'issues_read' "$DETAIL" >/dev/null || fail "$DETAIL must gate on issues_read"
grep -n 'organization_id' "$DETAIL" >/dev/null || fail "$DETAIL must scope by organization_id"

grep -n 'IssueComment' "$DETAIL" >/dev/null \
  || fail "$DETAIL must load IssueComment timeline from DB"
grep -nE '#\[route\(POST|/reply' "$DETAIL" >/dev/null \
  || fail "$DETAIL must expose POST reply route"
grep -n 'opened_by_user_id' "$LIST" >/dev/null \
  || fail "$LIST must persist opened_by_user_id on create"
grep -n 'struct IssueComment' src/models/mod.rs >/dev/null \
  || fail "models must define IssueComment"

# Support-side timeline authors must display as Vauban Support.
grep -n 'Vauban Support' "$DETAIL" >/dev/null \
  || fail "$DETAIL must label support-side authors as Vauban Support"

# No hardcodéd Concept relative-date fixtures.
if grep -nE '"3h ago"|"Jun 20"|"Jun 23"' "$DETAIL" "$LIST" src/app/org.rs >/dev/null 2>&1; then
  fail "issue/dashboard UI must not hardcode relative-date fixtures"
fi

ADMIN_LIST="src/app/admin/issues.rs"
ADMIN_DETAIL="src/app/admin/issues/issue_key.rs"
[[ -f "$ADMIN_LIST" ]] || fail "missing $ADMIN_LIST"
[[ -f "$ADMIN_DETAIL" ]] || fail "missing $ADMIN_DETAIL"
grep -n 'require_staff' "$ADMIN_LIST" >/dev/null || fail "$ADMIN_LIST must gate with require_staff"
grep -n 'issues_read' "$ADMIN_LIST" >/dev/null || fail "$ADMIN_LIST must gate on issues_read"
grep -n 'Vauban Support' "$ADMIN_DETAIL" >/dev/null \
  || fail "$ADMIN_DETAIL must label support-side authors as Vauban Support"
grep -nE '#\[route\(POST|/reply' "$ADMIN_DETAIL" >/dev/null \
  || fail "$ADMIN_DETAIL must expose POST reply route"
grep -n 'ISSUE_ROLE_SUPPORT' "$ADMIN_DETAIL" >/dev/null \
  || fail "$ADMIN_DETAIL staff replies must use ISSUE_ROLE_SUPPORT"

echo "check_portal_issues: OK"
