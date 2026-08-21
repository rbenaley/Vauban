#!/usr/bin/env bash
# Structural invariants for issue notification mail (outbox + policy).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "check_issue_notify: $*" >&2
  exit 1
}

for f in config/vcp.conf config/default.toml config/development.toml config/testing.toml; do
  grep -n '\[issues.notify\]' "$f" >/dev/null \
    || fail "$f must define [issues.notify]"
  grep -n 'exclude_actor' "$f" >/dev/null \
    || fail "$f must set exclude_actor"
  grep -n 'support_comment' "$f" >/dev/null \
    || fail "$f must list support_comment in company_events"
done

[[ -f src/issue_notify.rs ]] || fail "missing src/issue_notify.rs"
[[ -f email/issue-event.html ]] || fail "missing email/issue-event.html"
[[ -f toasty/migrations/0018_issue_mail_outbox.sql ]] \
  || fail "missing toasty/migrations/0018_issue_mail_outbox.sql"

grep -n 'enqueue_issue_notify' src/app/org/issues.rs >/dev/null \
  || fail "org issue create must call enqueue_issue_notify"
grep -n 'enqueue_issue_notify' src/app/org/issues/issue_key.rs >/dev/null \
  || fail "org issue comment must call enqueue_issue_notify"
grep -n 'enqueue_issue_notify' src/app/admin/issues/issue_key.rs >/dev/null \
  || fail "admin issue comment must call enqueue_issue_notify"
grep -n 'enqueue_issue_notify' src/issue_status.rs >/dev/null \
  || fail "advance_issue must call enqueue_issue_notify"
grep -n 'AdvanceOutcome::Applied' src/issue_status.rs >/dev/null \
  || fail "FSM persist must distinguish Applied"
grep -n 'NotifyEvent::Status' src/issue_status.rs >/dev/null \
  || fail "FSM enqueue must use NotifyEvent::Status"
grep -n 'start_issue_notify_drain' src/main.rs >/dev/null \
  || fail "src/main.rs must spawn start_issue_notify_drain"
grep -n 'IssueMailOutbox' src/db.rs >/dev/null \
  || fail "src/db.rs must register IssueMailOutbox"

if grep -n 'User::all()' src/issue_notify.rs | grep -v 'filter' >/dev/null 2>&1; then
  # Loaders must chain filter (no unscoped User::all().exec).
  if grep -nE 'User::all\(\)[[:space:]]*\.exec' src/issue_notify.rs >/dev/null; then
    fail "src/issue_notify.rs must not User::all().exec() without filter"
  fi
fi

if grep -nE 'portal_role\s*==\s*"' src/app/org/issues.rs src/app/org/issues/issue_key.rs \
  src/app/admin/issues/issue_key.rs >/dev/null 2>&1; then
  fail "issue handlers must not string-compare portal_role"
fi

if grep -n 'enqueue_issue_notify' src/db.rs >/dev/null; then
  fail "seed / db.rs must not enqueue issue notify"
fi
grep -n 'upsert_by_issue_id_and_event_and_source_id_and_recipient_user_id' src/issue_notify.rs >/dev/null \
  || fail "enqueue must use IssueMailOutbox upsert_by unique key"

echo "check_issue_notify: OK"
