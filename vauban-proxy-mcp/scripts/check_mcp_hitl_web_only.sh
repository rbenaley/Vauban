#!/usr/bin/env bash
# HITL approve / deny is a human decision: a logged-in user with TOTP,
# CSRF, `sessions:supervise`, not the requester. It goes through one web
# path only and never through /api/v1, where an API key (possibly the
# agent's own) authenticates.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
web=vauban-web/src
fail=0

prod() {
  awk 'FNR == 1 { skip=0; held=0 }
       skip { next }
       /^#\[cfg\(test\)\]$/ { held=1; next }
       held { held=0; if ($0 ~ /^(pub(\(crate\))? )?mod [A-Za-z0-9_]+ \{/) { skip=1; next } }
       { print FILENAME ":" FNR ":" $0 }' "$@"
}

rs_files() { find "$web" -name '*.rs' | sort; }

# Every call site of a seam must live in the expected file.
only_in() {
  local needle="$1" allowed="$2" hits
  # shellcheck disable=SC2046
  hits="$(prod $(rs_files) | grep -F -- "$needle" | grep -v -F "$allowed:" || true)"
  if [[ -n "$hits" ]]; then
    printf '%s\n' "$hits" >&2
    echo "[lint] '$needle' outside $allowed (HITL decisions are web-only)" >&2
    fail=1
  fi
}

# Wire message → built only by the proxy client.
only_in 'Message::McpHitlDecision {' "$web/ipc/proxy_mcp.rs"
# Proxy client → called only by the decision service.
only_in '.hitl_decision(' "$web/services/mcp_control.rs"
# Decision service → called only by the logged-in web handler.
only_in 'mcp_control::hitl_decide(' "$web/handlers/web/mcp_hitl.rs"

# No API route may reach the decision path.
if grep -R -n -E 'hitl|hitl_decide|approve|deny' "$web/handlers/api/mcp_sessions.rs" \
     | grep -v -E '^\S+:[0-9]+:\s*//' | grep -v -i 'justification'; then
  echo "[lint] /api/v1 MCP handler mentions a HITL decision" >&2
  fail=1
fi
api_mcp_routes="$(grep -n -o '"/api/v1/mcp[^"]*"' "$web/main.rs" | sort -u || true)"
if [[ "$(printf '%s\n' "$api_mcp_routes" | grep -c . || true)" -ne 1 ]] \
   || ! printf '%s\n' "$api_mcp_routes" | grep -q '"/api/v1/mcp/sessions"'; then
  printf '%s\n' "$api_mcp_routes" >&2
  echo "[lint] /api/v1 exposes MCP routes other than /api/v1/mcp/sessions (open only)" >&2
  fail=1
fi

# The web handler re-asserts the human gates.
handler="$web/handlers/web/mcp_hitl.rs"
for gate in 'auth_user: WebAuthUser' 'perms.sessions_supervise' 'validate_double_submit(' \
            'pending.requester_user_id == auth_user.uuid'; do
  if ! grep -q -F "$gate" "$handler"; then
    echo "[lint] $handler lost the HITL gate: $gate" >&2
    fail=1
  fi
done
# The proxy re-checks SoD and expiry whatever web sent.
if ! grep -q -F 'hitl_decision_blocked(' vauban-proxy-mcp/src/main.rs; then
  echo "[lint] proxy-mcp must re-check HITL decisions (hitl_decision_blocked)" >&2
  fail=1
fi

exit "$fail"
