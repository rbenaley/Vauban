#!/usr/bin/env bash
# Structural pins for Docs Markdown export/import CLI.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() { echo "check_docs_bundle: $*" >&2; exit 1; }

BUNDLE=src/docs_bundle.rs
MAIN=src/main.rs
CLI=src/cli.rs

[[ -f "$BUNDLE" ]] || fail "missing $BUNDLE"
grep -n 'serialize_markdown\|parse_markdown' "$BUNDLE" >/dev/null \
  || fail "$BUNDLE must serialize/parse Markdown frontmatter"
grep -n 'bundle_filename' "$BUNDLE" >/dev/null \
  || fail "$BUNDLE must define bundle_filename"
grep -n 'export_articles_to_dir' "$BUNDLE" >/dev/null \
  || fail "$BUNDLE must export articles to a directory"
grep -n 'import_articles_from_dir' "$BUNDLE" >/dev/null \
  || fail "$BUNDLE must import articles from a directory"
grep -n 'unpublish_other_published' "$BUNDLE" >/dev/null \
  || fail "$BUNDLE import must enforce publish exclusivity"
grep -n 'DOC_CATEGORIES' "$BUNDLE" >/dev/null \
  || fail "$BUNDLE must validate categories against DOC_CATEGORIES"

grep -n '"docs"' "$MAIN" >/dev/null || fail "$MAIN must dispatch docs command"
grep -n 'export_articles_to_dir\|import_articles_from_dir' "$MAIN" >/dev/null \
  || fail "$MAIN must call docs_bundle export/import"
grep -n 'docs export' "$CLI" >/dev/null || fail "$CLI usage must list docs export"
grep -n 'docs import' "$CLI" >/dev/null || fail "$CLI usage must list docs import"

grep -n 'docs-export\|docs-import' Justfile >/dev/null \
  || fail "Justfile must wrap docs-export / docs-import"

[[ -f docs/runbooks/docs_bundle_smoke_test.md ]] \
  || fail "missing docs/runbooks/docs_bundle_smoke_test.md"

echo "check_docs_bundle: OK"
