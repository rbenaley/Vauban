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
# The leaf does not listen. Test helpers may still bind a fake upstream.
for needle in 'MCP_LISTEN_ADDR' 'VAUBAN_MCP_BIND_ADDR'; do
  if grep -R -n -F -I -- "$needle" src Cargo.toml; then
    echo "forbidden listener env: $needle" >&2
    fail=1
  fi
done
prod=$(awk 'BEGIN{p=1} /mod gwt_tests/{p=0} p' src/main.rs)
if printf '%s\n' "$prod" | grep -n -F 'TcpListener::bind'; then
  echo "production leaf must not bind a TCP listener" >&2
  fail=1
fi
exit "$fail"
