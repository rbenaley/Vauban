#!/usr/bin/env bash
# JSON-RPC error codes returned to agents are wire (MCP Arch §9, ADR 004
# "Frozen MCP ordinals"). They are defined once, in rpc_codes.rs (and the
# Mission Seal pair in shared::mcp_mandate); production code names the
# constant. Tests keep the literal: that is what pins the value.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
fail=0

prod() {
  awk 'FNR == 1 { skip=0; held=0 }
       skip { next }
       /^#\[cfg\(test\)\]$/ { held=1; next }
       held { held=0; if ($0 ~ /^(pub(\(crate\))? )?mod [A-Za-z0-9_]+ \{/) { skip=1; next } }
       { print FILENAME ":" FNR ":" $0 }' "$@"
}

files=()
for f in vauban-proxy-mcp/src/*.rs; do
  case "$f" in
    *_tests.rs|*/test_upstream.rs|*/rpc_codes.rs) ;;
    *) files+=("$f") ;;
  esac
done

# Code text only: drop comments before looking for a literal.
literal='-32(0[0-9]{2}|6[0-9]{2})([^0-9]|$)'
hits="$(prod "${files[@]}" | sed -E 's#//.*$##' | grep -E -- "$literal" || true)"
if [[ -n "$hits" ]]; then
  printf '%s\n' "$hits" >&2
  echo "[lint] raw JSON-RPC code in proxy-mcp: use rpc_codes::* (single source)" >&2
  fail=1
fi

for f in vauban-proxy-mcp/src/rpc_codes.rs shared/src/mcp_mandate.rs; do
  if [[ ! -f "$f" ]]; then
    echo "[lint] missing code source $f" >&2
    fail=1
  fi
done
dups="$(grep -h -o -E 'pub const [A-Z_]+: i32 = -32[0-9]{3}' \
          vauban-proxy-mcp/src/rpc_codes.rs shared/src/mcp_mandate.rs \
        | grep -o -E -- '-32[0-9]{3}' | sort | uniq -d)"
if [[ -n "$dups" ]]; then
  echo "[lint] JSON-RPC code defined twice: $dups" >&2
  fail=1
fi

exit "$fail"
