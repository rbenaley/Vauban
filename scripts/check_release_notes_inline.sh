#!/usr/bin/env bash
# Structural invariants for release-note inline ``code`` rendering.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "check_release_notes_inline: $*" >&2
  exit 1
}

HELPER="src/release_notes.rs"
COMP="src/app/_components/note_inline.rs"
BUILDS="src/app/org/builds.rs"
ORG="src/app/org/dashboard_tiles.rs"
CSS="styles.css"

[[ -f "$HELPER" ]] || fail "missing $HELPER"
[[ -f "$COMP" ]] || fail "missing $COMP"

grep -n 'fn parse_inline_code' "$HELPER" >/dev/null \
  || fail "$HELPER must define parse_inline_code"
grep -n 'enum InlineSegment' "$HELPER" >/dev/null \
  || fail "$HELPER must define InlineSegment"
grep -n 'InlineSegment::Code' "$HELPER" >/dev/null \
  || fail "$HELPER must emit Code segments"

grep -n 'vb-inline-code' "$COMP" >/dev/null \
  || fail "$COMP must render <code class=\"vb-inline-code\">"
grep -n 'parse_inline_code' "$COMP" >/dev/null \
  || fail "$COMP must call parse_inline_code"
grep -n 'note_inline_text' "$COMP" >/dev/null \
  || fail "$COMP must expose note_inline_text"

grep -n 'note_inline_text' "$BUILDS" >/dev/null \
  || fail "$BUILDS changelog must call note_inline_text"
grep -n 'note_inline_text' "$ORG" >/dev/null \
  || fail "$ORG dashboard Latest build notes must call note_inline_text"
grep -n 'docs_formatted_body' src/app/org/docs/doc.rs >/dev/null \
  || fail "KB article modal must render via docs_formatted_body"
grep -n 'note_inline_text' src/app/_components/docs_formatted.rs >/dev/null \
  || fail "docs_formatted_body must call note_inline_text for prose chips"

# Do not leave plain (text) as the only changelog body on those surfaces.
if grep -nE '^\s*<span>\(text\)</span>\s*$' "$BUILDS" >/dev/null 2>&1; then
  fail "$BUILDS must not render raw (text) for note bodies (use note_inline_text)"
fi

grep -n '\.vb-inline-code' "$CSS" >/dev/null \
  || fail "$CSS must style .vb-inline-code"
grep -n "JetBrains Mono\|ui-monospace\|monospace" "$CSS" >/dev/null \
  || fail "$CSS .vb-inline-code must use a monospace stack"

echo "check_release_notes_inline: ok"
