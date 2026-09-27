#!/usr/bin/env bash
# Fail if the MCP proxy still contains lab escape hatches.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
needles=(
  'MCP_ALLOW_REQWEST'
  'MCP_DEV_CONTROL_PLANE'
  'MCP_LAB_AUTO_APPROVE'
  'MCP_CLIENTINFO_PIN'
  'reqwest'
  'route("/health"'
  'route("/session"'
)
fail=0
# grep, not rg: just lint runs on hosts where ripgrep is not on PATH.
# src and Cargo.toml only, so this script's own needle list is not a hit.
for needle in "${needles[@]}"; do
  if grep -R -n -F -I -- "$needle" src Cargo.toml; then
    echo "forbidden lab escape: $needle" >&2
    fail=1
  fi
done
exit "$fail"
