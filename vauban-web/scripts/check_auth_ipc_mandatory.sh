#!/usr/bin/env bash
# Auth IPC is mandatory.
#
# vauban-web must refuse to boot without a channel to vauban-auth, and
# production code must not hash or verify passwords through the in-process
# AuthService. Calls inside #[cfg(test)] modules are allowed (fixtures and
# unit tests). The method definitions themselves do not match the call
# pattern this script greps for.
#
# Discovered by `just lint`.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MAIN="${ROOT}/src/main.rs"
errors=0

fail() {
    echo "check_auth_ipc_mandatory.sh: $*" >&2
    errors=$((errors + 1))
}

if ! grep -q 'fn init_auth_client() -> anyhow::Result' "${MAIN}"; then
    fail "init_auth_client() must return anyhow::Result"
fi

# Unit tests call init_auth_client() to observe the error. The boot
# contract is the production prefix, before the first #[cfg(test)] module.
prod="$(awk 'BEGIN { keep = 1 } /^#\[cfg\(test\)\]/ { keep = 0 } keep' "${MAIN}")"

if ! grep -q 'init_auth_client()?' <<<"${prod}"; then
    fail "main must call init_auth_client()?"
fi

bare="$(grep -n 'init_auth_client()' <<<"${prod}" \
    | grep -v 'fn init_auth_client()' \
    | grep -v 'init_auth_client()?' || true)"
if [[ -n "${bare}" ]]; then
    fail "init_auth_client() called without ?: ${bare}"
fi

# Production lines only. A #[cfg(test)] module is skipped until its braces
# return to zero. State resets at each file.
hits="$(find "${ROOT}/src" -name '*.rs' -print | sort | xargs awk '
function braces(s,    i, c, n) {
    n = 0
    for (i = 1; i <= length(s); i++) {
        c = substr(s, i, 1)
        if (c == "{") n++
        else if (c == "}") n--
    }
    return n
}
FNR == 1 { depth = 0; skipping = 0; pending = 0 }
{
    if (skipping) {
        depth += braces($0)
        if (depth <= 0) skipping = 0
        next
    }
    if (pending) {
        if ($0 ~ /^[[:space:]]*#\[/ || $0 ~ /^[[:space:]]*$/) next
        if ($0 ~ /^[[:space:]]*mod[[:space:]]/) {
            pending = 0
            depth = braces($0)
            if (depth > 0) skipping = 1
            next
        }
        pending = 0
    }
    if ($0 ~ /^[[:space:]]*#\[cfg\(test\)\]/) {
        pending = 1
        next
    }
    if ($0 ~ /auth_service\.hash_password\(/ || $0 ~ /auth_service\.verify_password\(/) {
        stripped = $0
        sub(/^[[:space:]]+/, "", stripped)
        if (stripped ~ /^\/\//) next
        printf "%s:%d:%s\n", FILENAME, FNR, $0
    }
}
')"

if [[ -n "${hits}" ]]; then
    fail "in-process password call in production source:"
    echo "${hits}" >&2
fi

if [[ "${errors}" -ne 0 ]]; then
    echo "check_auth_ipc_mandatory.sh: FAILED" >&2
    exit 1
fi

echo "check_auth_ipc_mandatory.sh: OK"
