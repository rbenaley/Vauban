#!/usr/bin/env bash
# Structural pins for Support-only issue comment edit.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "check_issue_comment_edit: $*" >&2
  exit 1
}

[[ -f src/issue_comment_edit.rs ]] || fail "missing src/issue_comment_edit.rs"
[[ -f toasty/migrations/0019_issue_comment_edited_at.sql ]] \
  || fail "missing 0019_issue_comment_edited_at.sql"

grep -n 'fn can_edit_support_comment' src/issue_comment_edit.rs >/dev/null \
  || fail "src/issue_comment_edit.rs must define can_edit_support_comment"
grep -n 'admin_view' src/issue_comment_edit.rs >/dev/null \
  || fail "edit gate must require admin_view"
grep -n 'issues_write' src/issue_comment_edit.rs >/dev/null \
  || fail "edit gate must require issues_write"

ADMIN="src/app/admin/issues/issue_key.rs"
ORG="src/app/org/issues/issue_key.rs"
grep -nE '#\[route\(POST "/admin/issues/\{issue_key\}/edit-comment"\)' "$ADMIN" >/dev/null \
  || fail "$ADMIN must expose POST edit-comment"
grep -n 'decorate_support_edit\|can_edit_support_comment' "$ADMIN" >/dev/null \
  || fail "$ADMIN must decorate Support edit chrome"
if grep -nE 'edit-comment' "$ORG" >/dev/null 2>&1; then
  fail "$ORG must not expose comment edit"
fi
if grep -n 'can_edit: true' "$ORG" >/dev/null 2>&1; then
  fail "$ORG must not enable can_edit"
fi

grep -n 'edited_at' src/models/mod.rs >/dev/null \
  || fail "IssueComment must persist edited_at"
grep -n '0019_issue_comment_edited_at.sql' toasty/history.toml >/dev/null \
  || fail "history.toml must list 0019"

echo "check_issue_comment_edit: OK"
