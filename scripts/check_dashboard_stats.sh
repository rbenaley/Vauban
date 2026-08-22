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
DASH="src/app/org/dashboard_tiles.rs"
PAGE="src/app/org.rs"

[[ -f "$HELPERS" ]] || fail "missing $HELPERS"
grep -n 'fn summarize_issue_stats' "$HELPERS" >/dev/null \
  || fail "$HELPERS must define summarize_issue_stats"
grep -n 'fn latest_issue_by_updated_at' "$HELPERS" >/dev/null \
  || fail "$HELPERS must define latest_issue_by_updated_at"
grep -n 'DASHBOARD_ISSUES_CAP' "$HELPERS" >/dev/null \
  || fail "$HELPERS must define DASHBOARD_ISSUES_CAP"

# OPEN ISSUES tile = FSM Open only (not !issue_is_closed / "non-closed").
grep -n 'ISSUE_STATUS_OPEN' "$HELPERS" >/dev/null \
  || fail "$HELPERS must count ISSUE_STATUS_OPEN for the open tile"
grep -n 'ISSUE_STATUS_IN_ANALYSIS' "$HELPERS" >/dev/null \
  || fail "$HELPERS must count ISSUE_STATUS_IN_ANALYSIS for the analysis tile"
if grep -n 'issue_is_closed' "$HELPERS" >/dev/null; then
  fail "$HELPERS must not use issue_is_closed for dashboard tiles (double-counts In analysis)"
fi
grep -n 'summarize_open_excludes_in_analysis_and_terminal' "$HELPERS" >/dev/null \
  || fail "$HELPERS must keep the Open-vs-In-analysis regression unit test"

grep -n 'summarize_issue_stats' "$DASH" >/dev/null \
  || fail "$DASH must call summarize_issue_stats"
grep -n 'DASHBOARD_ISSUES_CAP' "$DASH" >/dev/null \
  || fail "$DASH must cap dashboard issues fetch"
grep -n 'organization_id().eq' "$DASH" >/dev/null \
  || fail "$DASH must filter issues by organization_id"
grep -n '#\[memoize\]' "$DASH" >/dev/null \
  || fail "$DASH must memoize dashboard loaders"
# Reject the old multi-COUNT pattern for issue tiles.
if grep -nE 'ISSUE_STATUS_RESOLVED|ISSUE_STATUS_CLOSED' "$DASH" >/dev/null; then
  fail "$DASH must not COUNT by ISSUE_STATUS_* for dashboard tiles (use summarize_issue_stats)"
fi
issue_alls=$(grep -c 'Issue::all()' "$DASH" || true)
if [[ "$issue_alls" -ne 1 ]]; then
  fail "$DASH must call Issue::all() exactly once (got $issue_alls)"
fi

# Page composes sibling #[component] tiles (0.6 concurrent I/O).
grep -n 'dash_stat_build' "$PAGE" >/dev/null \
  || fail "$PAGE must compose dash_stat_build"
grep -n 'dash_stat_open' "$PAGE" >/dev/null \
  || fail "$PAGE must compose dash_stat_open"
grep -n 'dash_stat_analysis' "$PAGE" >/dev/null \
  || fail "$PAGE must compose dash_stat_analysis"
grep -n 'dash_card_docs' "$PAGE" >/dev/null \
  || fail "$PAGE must compose dash_card_docs"
grep -n 'dash_activity' "$PAGE" >/dev/null \
  || fail "$PAGE must compose dash_activity"
grep -n '#\[component\]' "$DASH" >/dev/null \
  || fail "$DASH must declare sibling dashboard components"

# Recent activity is copy-only (no wall-clock / relative dates).
grep -n 'issue_activity_copy' "$DASH" >/dev/null \
  || fail "$DASH must use issue_activity_copy for activity text"
grep -n 'fn issue_activity_copy' "$HELPERS" >/dev/null \
  || fail "$HELPERS must define issue_activity_copy"
if grep -nE 'format_relative|format_unix_local|build_released_on|browser_tz' "$DASH" >/dev/null; then
  fail "$DASH recent activity must not render dates"
fi
if grep -nE 'format_relative|format_unix_local|build_released_on|browser_tz' "$PAGE" >/dev/null; then
  fail "$PAGE recent activity must not render dates"
fi
grep -n 'vb-grid-2' "$PAGE" >/dev/null \
  || fail "$PAGE must use vb-grid-2 for activity / latest-build panels"
grep -nE '\.vb-grid-2 \{ display: grid; grid-template-columns: 1fr 1fr;' styles.css >/dev/null \
  || fail "styles.css .vb-grid-2 must be equal 1fr 1fr columns"

echo "check_dashboard_stats: OK"
