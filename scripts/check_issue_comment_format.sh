#!/usr/bin/env bash
# Structural pins: docs dialect on issue comment bodies only (not titles / mail).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "check_issue_comment_format: $*" >&2
  exit 1
}

THUMBS="src/app/issue_thumbs.rs"
NOTIFY="src/issue_notify.rs"
FORMATTED="src/app/_components/docs_formatted.rs"

[[ -f "$FORMATTED" ]] || fail "missing $FORMATTED"
grep -n 'docs_body::parse' "$FORMATTED" >/dev/null \
  || fail "$FORMATTED must parse via docs_body::parse"
grep -n 'vb-pre' "$FORMATTED" >/dev/null \
  || fail "$FORMATTED must emit vb-pre for fences"
grep -n 'docs_formatted_body' "$THUMBS" >/dev/null \
  || fail "$THUMBS must render comment bodies via docs_formatted_body"

# Opener (issue.details) stays plain text.
grep -n '(opener_body)' "$THUMBS" >/dev/null \
  || fail "$THUMBS opener bubble must interpolate opener_body as raw text"
if grep -n 'docs_formatted_body(body: &opener' "$THUMBS" >/dev/null 2>&1; then
  fail "$THUMBS opener must not use docs_formatted_body"
fi

# Titles stay raw interpolations.
for f in src/app/org/issues/issue_key.rs src/app/admin/issues/issue_key.rs \
  src/app/org/issues/search_shard.rs src/app/admin/issues/search_shard.rs; do
  if grep -n 'docs_formatted_body\|docs_body::parse' "$f" | grep -qi title; then
    fail "$f must not format issue titles"
  fi
done

# Mail excerpt stays raw (no dialect flatten / HTML).
if grep -n 'docs_body::parse\|docs_formatted_body' "$NOTIFY" >/dev/null 2>&1; then
  fail "$NOTIFY must not format mail excerpts"
fi
grep -n 'fn excerpt_text' "$NOTIFY" >/dev/null \
  || fail "$NOTIFY must keep excerpt_text"

grep -n 'DIALECT_HINT' src/app/org/issues/issue_key.rs >/dev/null \
  || fail "org reply must show DIALECT_HINT"
grep -n 'DIALECT_HINT' src/app/admin/issues/issue_key.rs >/dev/null \
  || fail "admin reply must show DIALECT_HINT"
grep -n '\.vb-issue-prose' styles.css >/dev/null \
  || fail "styles.css must style .vb-issue-prose"

echo "check_issue_comment_format: OK"
