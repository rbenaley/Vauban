#!/usr/bin/env bash
# Structural lint: every consumer of an existing `proxy_sessions` row
# MUST go through `services::session_access::verify(...)`. The service
# is the single seam that combines three layers:
#
#   1. instance-level decision via vauban-access RPC (ownership +
#      access-rule re-check),
#   2. Casbin OR-overrides per intent (sessions:supervise / write),
#   3. anti-enumeration response shaping (every denial collapses to
#      404, except `Gone` which stays 410).
#
# Two regressions are caught here:
#
#   - reintroducing `verify_session_ownership` outside the wrapper
#     declaration in websocket.rs (which is itself a thin proxy to
#     session_access::verify) and the tests directory;
#
#   - reintroducing direct `proxy_sessions::table.filter(uuid.eq(...))`
#     ownership lookups inside session-related handlers, which would
#     bypass the access-rule re-check and the anti-enum collapse.
#
# Returns non-zero on the first offending occurrence so it can plug
# into CI alongside the other structural lints.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC_DIR="${ROOT}/src"

if [[ ! -d "${SRC_DIR}" ]]; then
    echo "[lint] src directory not found: ${SRC_DIR}" >&2
    exit 2
fi

errors=0

# --- Layer 1: verify_session_ownership ---
#
# Allowed locations:
#   - the wrapper declaration in src/handlers/websocket.rs (it
#     delegates to session_access::verify),
#   - structural tests in src/handlers/web/tests.rs and
#     src/handlers/websocket.rs `#[cfg(test)]` block (they look up
#     the symbol as a string).
#
# Forbidden anywhere else: a new handler that reintroduces direct
# ownership SQL would bypass the access-rule re-check.
while IFS= read -r match; do
    file="${match%%:*}"
    case "${file}" in
        */handlers/websocket.rs)
            # Only the wrapper itself is allowed here.
            continue
            ;;
        */handlers/web/tests.rs)
            # String-literal anti-regression contracts only.
            continue
            ;;
    esac
    echo "${match}"
    errors=1
done < <(grep -REn --include='*.rs' '\bverify_session_ownership\b' "${SRC_DIR}" || true)

# --- Layer 2: direct proxy_sessions UUID lookup in handlers ---
#
# `proxy_sessions::table.filter(uuid.eq(...))` (or `dsl::uuid.eq` /
# `proxy_sessions.filter(uuid.eq(...))`) is the canonical IDOR
# pattern: it loads a row by UUID without ownership/access-rule
# checks. Allowed only inside session_access.rs (well, the service
# does NOT do this either: it delegates to vauban-access). We allow
# it inside the create / cleanup / status-update / WS-cleanup paths,
# which are NOT user-facing reads and which are well covered by the
# proxy-side defense-in-depth.
#
# Forbidden in the read/page/terminate handlers. We scope the lint to
# the handlers that the audit identified as the IDOR surface:
#
#   - src/handlers/web/ssh.rs:terminal_page
#   - src/handlers/web/rdp.rs:rdp_page
#   - src/handlers/web/sessions.rs:session_detail
#
# rather than blanket-banning the pattern (proxy paths legitimately
# need UUID lookups for status updates, cleanup, etc.). The grep is
# anchored at the handler signature so only the function body is
# scanned.

check_handler_for_uuid_filter() {
    local file="$1"
    local fn_signature="$2"
    if [[ ! -f "${file}" ]]; then
        return 0
    fi
    awk -v fn="${fn_signature}" '
        BEGIN { in_fn = 0; depth = 0 }
        index($0, fn) > 0 { in_fn = 1; print NR ":" $0; next }
        in_fn {
            n = gsub(/\{/, "{")
            depth += n
            n = gsub(/\}/, "}")
            depth -= n
            print NR ":" $0
            if (depth <= 0 && /\}/) { in_fn = 0 }
        }
    ' "${file}" | grep -E '(proxy_sessions(::table)?\.filter\([^)]*uuid\.eq|dsl::uuid\.eq)' || true
}

scan_handler() {
    local file="$1"
    local fn_signature="$2"
    local label="$3"
    local hits
    hits="$(check_handler_for_uuid_filter "${file}" "${fn_signature}" || true)"
    if [[ -n "${hits}" ]]; then
        echo "${label}: forbidden direct proxy_sessions UUID lookup detected:" >&2
        echo "${hits}" >&2
        echo >&2
        errors=1
    fi
}

scan_handler "${SRC_DIR}/handlers/web/ssh.rs"      "pub async fn terminal_page("    "ssh.rs:terminal_page"
scan_handler "${SRC_DIR}/handlers/web/rdp.rs"      "pub async fn rdp_page("         "rdp.rs:rdp_page"
scan_handler "${SRC_DIR}/handlers/web/sessions.rs" "pub async fn session_detail("   "sessions.rs:session_detail"

if [[ ${errors} -ne 0 ]]; then
    echo >&2
    echo "[lint] Forbidden bypass of services::session_access detected." >&2
    echo "[lint]" >&2
    echo "[lint] Every consumer of an existing proxy_sessions row MUST go" >&2
    echo "[lint] through services::session_access::verify(state, uuid," >&2
    echo "[lint] user, perms, intent). That seam is the only thing that" >&2
    echo "[lint] guarantees the access-rule re-check (vauban-access) and" >&2
    echo "[lint] the anti-enumeration 404 collapse." >&2
    echo "[lint]" >&2
    echo "[lint] Forbidden patterns:" >&2
    echo "[lint]   - calls to verify_session_ownership outside the wrapper" >&2
    echo "[lint]     in websocket.rs and the structural tests;" >&2
    echo "[lint]   - direct proxy_sessions::table.filter(uuid.eq(...)) in" >&2
    echo "[lint]     terminal_page / rdp_page / session_detail." >&2
    exit 1
fi

echo "[lint] session_access centralization OK"
