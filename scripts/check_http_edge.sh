#!/usr/bin/env bash
# Structural invariants for HTTPS edge: Apache CLF access log + security headers.
# Uses grep so CI works without ripgrep on PATH.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "check_http_edge: $*" >&2
  exit 1
}

# Access log must wrap the per-connection HTTPS service and append to a file.
grep -n 'AccessLogService' src/tls/serve.rs >/dev/null \
  || fail "src/tls/serve.rs must wrap connections with AccessLogService"
grep -n 'format_common_log' src/tls/access_log.rs >/dev/null \
  || fail "src/tls/access_log.rs must define format_common_log"
grep -n 'OpenOptions::new' src/tls/access_log.rs >/dev/null \
  || fail "access log must open a file via OpenOptions"
grep -n '\.append(true)' src/tls/access_log.rs >/dev/null \
  || fail "access log file must be opened in append mode"
grep -n 'write_line' src/tls/access_log.rs >/dev/null \
  || fail "access log must write CLF lines via write_line"
# Startup may announce the path via info!; request CLF lines stay in the file.
grep -n 'info!(access_log' src/tls/access_log.rs >/dev/null \
  || fail "AccessLog::open must announce path via tracing under this module"
if grep -nE 'info!\("\{line\}"\)|info!\(\{line\}' src/tls/access_log.rs >/dev/null; then
  fail "request CLF lines must not be emitted via tracing::info!"
fi
grep -n 'access_log.write_line(&line)' src/tls/access_log.rs >/dev/null \
  || fail "AccessLogService must append CLF via write_line"

# Configured path per environment.
grep -n 'access_log_path' config/development.toml >/dev/null \
  || fail "development.toml must set server.access_log_path"
grep -n 'access_log_path' config/testing.toml >/dev/null \
  || fail "testing.toml must set server.access_log_path"
grep -n 'access_log_path = "/var/log/vcp-access.log"' config/vcp.conf >/dev/null \
  || fail "vcp.conf must set access_log_path to /var/log/vcp-access.log"
grep -n 'logs/' .gitignore >/dev/null \
  || fail ".gitignore must exclude the local logs/ directory"

# Trailing-slash canonicalization (wide redirect_permanent / 308 on GET/HEAD).
HELPERS="src/http_canonical.rs"
[[ -f "$HELPERS" ]] || fail "missing $HELPERS"
grep -n 'trailing_slash_redirect_location' "$HELPERS" >/dev/null \
  || fail "$HELPERS must define trailing_slash_redirect_location"
grep -n 'should_redirect_trailing_slash' "$HELPERS" >/dev/null \
  || fail "$HELPERS must define should_redirect_trailing_slash"
grep -n 'redirect_permanent' src/app.rs >/dev/null \
  || fail "src/app.rs must use topcoat redirect_permanent for trailing slashes"
grep -n 'trailing_slash_redirect_location' src/app.rs >/dev/null \
  || fail "src/app.rs security layer must call trailing_slash_redirect_location"
grep -n 'should_redirect_trailing_slash' src/app.rs >/dev/null \
  || fail "src/app.rs must gate trailing-slash redirects to safe methods"
if grep -nE 'MOVED_PERMANENTLY|moved_permanently' src/app.rs >/dev/null; then
  fail "src/app.rs must not hand-roll 301; use redirect_permanent (308)"
fi

# Dynamic responses must set the hardening headers (and no-store for HTML).
APP="src/app.rs"
grep -n 'no-store' "$APP" >/dev/null \
  || fail "$APP must set Cache-Control: no-store for dynamic responses"
grep -n 'nosniff' "$APP" >/dev/null \
  || fail "$APP must set X-Content-Type-Options: nosniff"
grep -n "frame-ancestors 'none'" "$APP" >/dev/null \
  || fail "$APP must set CSP frame-ancestors 'none'"
grep -n 'geolocation=(), camera=(), microphone=()' "$APP" >/dev/null \
  || fail "$APP must set Permissions-Policy camera/mic/geo deny"
grep -n 'header::CACHE_CONTROL' "$APP" >/dev/null \
  || fail "$APP must preserve existing Cache-Control (assets)"

# Must not overwrite asset immutable cache when already present.
grep -n 'contains_key(header::CACHE_CONTROL)' "$APP" >/dev/null \
  || fail "$APP must only set no-store when Cache-Control is absent"
# Handler Err(redirect) must become a Response in-layer so headers still apply.
grep -n 'error.into_response(cx)' "$APP" >/dev/null \
  || fail "$APP security layer must convert next.run Err via into_response"
if grep -nE 'next\.run\(cx, body\)\.await\?' "$APP" >/dev/null; then
  fail "$APP must not ?-propagate next.run Err (skips headers on redirects)"
fi

# TLS handshake failure coalescing (ops TRACE, not request CLF).
SERVE="src/tls/serve.rs"
grep -n 'note_handshake_failure' "$SERVE" >/dev/null \
  || fail "$SERVE must call note_handshake_failure on accept Err"
grep -n 'flush_handshake_failures' "$SERVE" >/dev/null \
  || fail "$SERVE must flush handshake failures on shutdown"
grep -n 'HANDSHAKE_LOG_IDLE' "$SERVE" >/dev/null \
  || fail "$SERVE must define HANDSHAKE_LOG_IDLE"
grep -n 'TLS handshake failed error=' "$SERVE" >/dev/null \
  || fail "$SERVE must emit coalesced TLS handshake failed template"
grep -n 'count={count}' "$SERVE" >/dev/null \
  || fail "$SERVE must include count=N in coalesced handshake log"
grep -n 'trace!' "$SERVE" >/dev/null \
  || fail "handshake coalescing must use trace! (benign client noise)"
if grep -nE 'debug!\("TLS handshake failed' "$SERVE" >/dev/null; then
  fail "handshake coalescing must not use debug! for TLS handshake failed"
fi
grep -n 'struct HandshakeFailureLog' "$SERVE" >/dev/null \
  || fail "$SERVE must expose HandshakeFailureLog for pyramid tests"

echo "check_http_edge: OK"
