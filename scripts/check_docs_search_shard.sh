#!/usr/bin/env bash
# Structural invariants for docs search shard surface.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "check_docs_search_shard: $*" >&2
  exit 1
}

SHARD="src/app/org/docs/search_shard.rs"
DOCS="src/app/org/docs.rs"

[[ -f "$SHARD" ]] || fail "missing $SHARD"

grep -nE '#\[shard\]' "$SHARD" >/dev/null || fail "$SHARD must define #[shard]"
grep -n 'docs_search_results' "$SHARD" >/dev/null || fail "$SHARD must export docs_search_results"
grep -n 'require_org' "$SHARD" >/dev/null || fail "$SHARD must re-check require_org"
grep -n 'docs_read' "$SHARD" >/dev/null || fail "$SHARD must re-check docs_read"
grep -n 'load_filtered_docs' "$SHARD" >/dev/null || fail "$SHARD must use load_filtered_docs"

grep -n 'docs_search_results' "$DOCS" >/dev/null || fail "$DOCS must invoke docs_search_results shard"

echo "check_docs_search_shard: OK"
