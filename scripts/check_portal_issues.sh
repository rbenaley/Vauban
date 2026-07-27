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

grep -n 'method="POST"' "$NEW" >/dev/null || fail "$NEW must POST report form"
grep -n 'name="details"' "$NEW" >/dev/null || fail "$NEW must include details field"

grep -n 'issue.details' "$DETAIL" >/dev/null || fail "$DETAIL must render issue.details"
grep -n 'issues_read' "$DETAIL" >/dev/null || fail "$DETAIL must gate on issues_read"
grep -n 'organization_id' "$DETAIL" >/dev/null || fail "$DETAIL must scope by organization_id"

echo "check_portal_issues: OK"
