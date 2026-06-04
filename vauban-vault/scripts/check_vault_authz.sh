#!/usr/bin/env bash
# VAU-002 -- structural lint: the vault MUST authorize every peer vault
# request against the per-peer capability matrix BEFORE doing any crypto.
#
# Regressions guarded against forever:
#
# 1. A peer vault verb reaching `handle_vault_request` WITHOUT first passing
#    `authz::is_authorized` (the pre-fix behavior: any peer could decrypt any
#    domain). Both `handle_peer_message` and `handle_supervisor_message` must
#    gate on the capability matrix.
#
# 2. The pre-fix unconditional forwarding arms
#    `other => handle_vault_request(channel, state, other)` -- both the peer
#    path and the "supervisor may forward in some topologies" path -- which
#    bypassed authorization entirely.
#
# 3. A fail-OPEN catch-all (`_ => true`) sneaking into the matrix, or the
#    fail-closed `_ => false` arm disappearing.
#
# 4. The anomaly counter (`requests_denied`) or the deny helper being dropped.
#
# Companion of:
#   - vauban-vault/src/authz.rs (mod tests: capability matrix)
#   - vauban-vault/src/main.rs (mod tests: VAU-002 behavioral + structural)
#   - vauban-web/tests/security/security_test.rs (vault structural pins)
#
# Returns non-zero on the first violation so it plugs into CI.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

errors=0

AUTHZ="${ROOT}/src/authz.rs"
MAIN="${ROOT}/src/main.rs"

# Fixed-string / regex presence helpers that read from a here-string. We
# deliberately avoid `printf ... | grep -q` because `grep -q` exits on the
# first match, closing the pipe; with `pipefail` set, the upstream `printf`
# then dies with SIGPIPE and the whole pipeline reports failure even though
# the pattern WAS found. Here-strings have no upstream process and so are
# immune to that false negative.
has() { grep -qF -- "$1" <<<"$2"; }
hasE() { grep -qE -- "$1" <<<"$2"; }

# ---- 1. authz.rs defines the matrix and is fail-closed ----
if [[ ! -f "${AUTHZ}" ]]; then
    echo "[lint] missing file: ${AUTHZ}" >&2
    exit 1
fi
# Strip Rust line comments so docs mentioning a token do not count.
stripped_authz="$(sed 's|//.*$||' "${AUTHZ}")"

for token in 'enum VaultPeer' 'fn is_authorized' 'VaultPeer::Supervisor' 'fn denied_response'; do
    if ! has "${token}" "${stripped_authz}"; then
        echo "[lint] forbidden: ${AUTHZ} no longer defines \`${token}\`"
        echo "       VAU-002: the per-peer capability matrix must stay intact."
        errors=1
    fi
done
if ! has '_ => false' "${stripped_authz}"; then
    echo "[lint] forbidden: ${AUTHZ} lost its fail-closed \`_ => false\` catch-all"
    echo "       VAU-002: is_authorized MUST default to deny."
    errors=1
fi
if has '_ => true' "${stripped_authz}"; then
    echo "[lint] forbidden: ${AUTHZ} contains a fail-OPEN \`_ => true\` arm"
    echo "       VAU-002: an unconditional allow re-opens the cross-domain hole."
    errors=1
fi

# ---- 2. main.rs wires the gate + anomaly counter ----
if [[ ! -f "${MAIN}" ]]; then
    echo "[lint] missing file: ${MAIN}" >&2
    exit 1
fi
stripped_main="$(sed 's|//.*$||' "${MAIN}")"

for token in 'mod authz;' 'requests_denied' 'fn deny_vault_request' 'VaultPeer::from_channel_label' 'VaultPeer::Supervisor'; do
    if ! has "${token}" "${stripped_main}"; then
        echo "[lint] forbidden: ${MAIN} no longer references \`${token}\`"
        echo "       VAU-002: the authorization gate / anomaly counter is missing."
        errors=1
    fi
done

# is_authorized MUST be called in BOTH handle_peer_message and
# handle_supervisor_message (>= 2 call sites).
authz_calls="$(grep -cF 'authz::is_authorized' <<<"${stripped_main}" || true)"
if [[ "${authz_calls}" -lt 2 ]]; then
    echo "[lint] forbidden: \`authz::is_authorized\` appears ${authz_calls} time(s) in ${MAIN}"
    echo "       VAU-002: BOTH handle_peer_message and handle_supervisor_message"
    echo "       must gate vault verbs through the capability matrix."
    errors=1
fi

# ---- 3. the pre-fix unguarded forwarding arm must be gone ----
if hasE '=>[[:space:]]*handle_vault_request\(' "${stripped_main}"; then
    echo "[lint] forbidden: ${MAIN} still forwards a vault verb directly via"
    echo "       \`=> handle_vault_request(...)\` (no authorization gate)."
    echo "       VAU-002: every call to handle_vault_request must be reached"
    echo "       only AFTER an is_authorized check."
    errors=1
fi

if [[ ${errors} -ne 0 ]]; then
    echo >&2
    echo "[lint] One or more VAU-002 vault authorization invariants violated." >&2
    echo "[lint] See vauban-vault/src/authz.rs and the VAU-002 tests in" >&2
    echo "[lint] vauban-vault/src/main.rs for the full coverage matrix." >&2
    exit 1
fi

echo "[lint] VAU-002: vault per-peer authorization intact (capability matrix"
echo "[lint]          fail-closed, both handlers gate before crypto, anomaly"
echo "[lint]          counter wired, no unguarded forwarding arm)"
