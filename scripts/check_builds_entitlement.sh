#!/usr/bin/env bash
# Structural invariants for builds download entitlement surface.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "check_builds_entitlement: $*" >&2
  exit 1
}

DL="src/app/org/builds/download.rs"
BUILDS="src/app/org/builds.rs"

[[ -f "$DL" ]] || fail "missing $DL"

grep -nE '#\[route\(POST' "$DL" >/dev/null || fail "$DL must expose POST download route"
grep -n 'builds_download' "$DL" >/dev/null || fail "$DL must gate on builds_download"
grep -n 'download not configured' "$DL" >/dev/null \
  || fail "$DL must return stable 'download not configured' message"
grep -n 'NOT_IMPLEMENTED\|StatusCode::NOT_IMPLEMENTED' "$DL" >/dev/null \
  || fail "$DL must return 501 NOT_IMPLEMENTED when authorized"
grep -n 'require_org' "$DL" >/dev/null || fail "$DL must call require_org"
grep -n 'forbidden' "$DL" >/dev/null || fail "$DL must fail closed with forbidden when missing perm"

grep -n '/download' "$BUILDS" >/dev/null || fail "$BUILDS UI must post to download route"
grep -n 'builds_download' "$BUILDS" >/dev/null || fail "$BUILDS must consult builds_download"

echo "check_builds_entitlement: OK"
