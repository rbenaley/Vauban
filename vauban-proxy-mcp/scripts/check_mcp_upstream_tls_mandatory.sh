#!/usr/bin/env bash
# ADR 010: every MCP upstream byte travels over TLS checked against the
# asset SPKI pin. No plaintext transport, no verifier bypass, no open or
# discover without a pin.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
proxy=vauban-proxy-mcp/src
fail=0

# Production source only: drop `#[cfg(test)] mod … {` blocks to EOF.
prod() {
  awk 'FNR == 1 { skip=0; held=0 }
       skip { next }
       /^#\[cfg\(test\)\]$/ { held=1; next }
       held { held=0; if ($0 ~ /^(pub(\(crate\))? )?mod [A-Za-z0-9_]+ \{/) { skip=1; next } }
       { print FILENAME ":" FNR ":" $0 }' "$@"
}

prod_files=()
for f in "$proxy"/*.rs; do
  case "$f" in
    *_tests.rs|*/test_upstream.rs) ;;
    *) prod_files+=("$f") ;;
  esac
done

# 1. The rustls `dangerous()` hook exists only to install the SPKI pin
#    verifier. Anywhere else it is a verification bypass.
if prod "${prod_files[@]}" | grep -v "^$proxy/tls_pin.rs:" | grep -E 'dangerous\(\)|client::danger'; then
  echo "[lint] rustls dangerous() outside tls_pin.rs (ADR 010)" >&2
  fail=1
fi
if ! grep -q 'impl ServerCertVerifier for PinningServerCertVerifier' "$proxy/tls_pin.rs"; then
  echo "[lint] tls_pin.rs must keep the SPKI pinning verifier" >&2
  fail=1
fi

# 2. The proxy never builds a plaintext upstream URL or transport.
if prod "${prod_files[@]}" | grep -E 'format!\("http://|Upstream::Plain|Transport::Plain'; then
  echo "[lint] plaintext upstream in proxy-mcp (ADR 010)" >&2
  fail=1
fi

# 3. One choke point: `upstream_over_tls` refuses a missing pin, then
#    pins TLS, then speaks HTTP. Open, discover and re-broker all go
#    through it; a second handshake call site would be a path around it.
for call in 'tls_pin::connect_pinned(' 'upstream_http::Upstream::handshake('; do
  n="$(prod "${prod_files[@]}" | grep -c -F "$call" || true)"
  if [[ "$n" -ne 1 ]]; then
    echo "[lint] proxy-mcp: $call must have exactly one production call site (upstream_over_tls), found $n" >&2
    fail=1
  fi
done
# grep -c, not -q: -q closes the pipe early and pipefail reports awk's SIGPIPE.
if [[ "$(prod "$proxy/main.rs" | grep -c '\.ok_or(TLS_PIN_REQUIRED)?;' || true)" -ne 1 ]]; then
  echo "[lint] upstream_over_tls must refuse a missing pin (TLS_PIN_REQUIRED)" >&2
  fail=1
fi
if [[ "$(prod "$proxy/main.rs" | grep -c 'upstream_over_tls(')" -lt 4 ]]; then
  echo "[lint] open, discover and re-broker must reach the upstream through upstream_over_tls" >&2
  fail=1
fi

# 4. Web always sends the pin it holds for the asset.
for f in vauban-web/src/services/mcp_session.rs vauban-web/src/services/mcp_discover.rs; do
  if ! grep -q 'upstream_tls_spki_pin = Some(mcp_upstream_tls_pin(&asset.connection_config)?)' "$f"; then
    echo "[lint] $f must send the asset SPKI pin (ADR 010)" >&2
    fail=1
  fi
done
if prod vauban-web/src/services/mcp_*.rs vauban-web/src/handlers/web/mcp*.rs \
     vauban-web/src/handlers/api/mcp_sessions.rs vauban-web/src/ipc/proxy_mcp.rs \
     | grep 'upstream_tls_spki_pin: None'; then
  echo "[lint] web must never open or discover an MCP upstream without a pin" >&2
  fail=1
fi

exit "$fail"
