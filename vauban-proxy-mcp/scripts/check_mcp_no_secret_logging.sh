#!/usr/bin/env bash
# MCP code never hands a credential to `tracing`: the upstream bearer, the
# vault blob, session tokens, `vbw_` / `vbn_` bearers, raw request headers.
# Message text may name them ("session token verify failed"); a field or
# format argument may not. Each tracing macro is joined across lines, its
# string literals removed, then the remaining tokens are checked.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"

files=()
for f in vauban-proxy-mcp/src/*.rs; do
  case "$f" in
    *_tests.rs|*/test_upstream.rs) ;;
    *) files+=("$f") ;;
  esac
done
files+=(
  vauban-web/src/services/mcp_*.rs
  vauban-web/src/handlers/web/mcp*.rs
  vauban-web/src/handlers/api/mcp_sessions.rs
  vauban-web/src/ipc/proxy_mcp.rs
  vauban-access/src/mcp_pdp.rs
)

macros() {
  awk 'FNR == 1 { skip=0; held=0; inmac=0 }
       skip { next }
       /^#\[cfg\(test\)\]$/ { held=1; next }
       held { held=0; if ($0 ~ /^(pub(\(crate\))? )?mod [A-Za-z0-9_]+ \{/) { skip=1; next } }
       {
         if (!inmac && $0 ~ /(trace|debug|info|warn|error)!\(/) { inmac=1; buf=""; depth=0; start=FNR }
         if (inmac) {
           buf = buf " " $0
           n = split($0, ch, "")
           for (i = 1; i <= n; i++) { if (ch[i] == "(") depth++; else if (ch[i] == ")") depth-- }
           if (depth <= 0) { print FILENAME ":" start ":" buf; inmac=0 }
         }
       }' "$@"
}

forbidden='bearer|credential|session_token|token_key|authorization|password|plaintext|secret|[^a-z_]token[^a-z_]|headers|vbw_|vbn_|raw_key'
hits="$(macros "${files[@]}" \
  | sed -E 's/"([^"\\]|\\.)*"//g' \
  | grep -i -E "$forbidden" || true)"
if [[ -n "$hits" ]]; then
  printf '%s\n' "$hits" | sed -E 's/  +/ /g' >&2
  echo "[lint] MCP tracing call carries a credential-bearing value" >&2
  exit 1
fi
