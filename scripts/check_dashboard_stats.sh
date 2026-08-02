#!/usr/bin/env bash
# Structural invariants for org dashboard issue stats aggregation.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "check_dashboard_stats: $*" >&2
  exit 1
}

HELPERS="src/dashboard_stats.rs"
DASH="src/app/org.rs"

[[ -f "$HELPERS" ]] || fail "missing $HELPERS"
grep -n 'fn summarize_issue_stats' "$HELPERS" >/dev/null \
  || fail "$HELPERS must define summarize_issue_stats"
grep -n 'fn latest_issue_by_updated_at' "$HELPERS" >/dev/null \
  || fail "$HELPERS must define latest_issue_by_updated_at"
grep -n 'DASHBOARD_ISSUES_CAP' "$HELPERS" >/dev/null \
  || fail "$HELPERS must define DASHBOARD_ISSUES_CAP"

grep -n 'summarize_issue_stats' "$DASH" >/dev/null \
  || fail "$DASH must call summarize_issue_stats"
grep -n 'DASHBOARD_ISSUES_CAP' "$DASH" >/dev/null \
  || fail "$DASH must cap dashboard issues fetch"
grep -n 'organization_id().eq' "$DASH" >/dev/null \
  || fail "$DASH must filter issues by organization_id"
# Reject the old multi-COUNT pattern for issue tiles.
if grep -nE 'ISSUE_STATUS_RESOLVED|ISSUE_STATUS_CLOSED' "$DASH" >/dev/null; then
  fail "$DASH must not COUNT by ISSUE_STATUS_* for dashboard tiles (use summarize_issue_stats)"
fi
issue_alls=$(grep -c 'Issue::all()' "$DASH" || true)
if [[ "$issue_alls" -ne 1 ]]; then
  fail "$DASH must call Issue::all() exactly once (got $issue_alls)"
fi

echo "check_dashboard_stats: OK"
