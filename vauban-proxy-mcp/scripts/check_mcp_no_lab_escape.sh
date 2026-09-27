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
for needle in "${needles[@]}"; do
  if rg -n --glob '!scripts/**' -F "$needle" src Cargo.toml; then
    echo "forbidden lab escape: $needle" >&2
    fail=1
  fi
done
exit "$fail"
