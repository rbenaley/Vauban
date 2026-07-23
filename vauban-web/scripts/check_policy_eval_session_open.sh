#!/usr/bin/env bash
# Structural lint: SSH/RDP session-open uses exactly one IssueSessionToken
# (policy + constraints + mint) before proxy_sessions INSERT, and must NOT
# call can_access_asset on the connect path (policy eval 3→2).
#
# Regressions guarded forever:
#
# 1. connect_ssh / connect_rdp reintroduce can_access_asset (extra access
#    trip; constraints come from SessionTokenIssued).
# 2. A second issue_session_token after INSERT (back to 3 evals with
#    AccessGuard).
# 3. issue_session_token moves after insert_into(proxy_sessions).
# 4. handle_issue_session_token stops propagating MFA/JIT/duration into
#    SessionTokenIssued.
# 5. submit_access_request loses can_access_asset (orthogonal path).
# 6. Proxies drop AccessGuard::authorize (defense-in-depth eval).
#
# Companion of:
#   - docs/runbooks/policy_eval_session_open_smoke_test.md
#   - vauban-web/tests/web/policy_eval_session_open_*_test.rs
#
# Returns non-zero on the first violation.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REPO="$(cd "${ROOT}/.." && pwd)"
SSH_RS="${ROOT}/src/handlers/web/ssh.rs"
RDP_RS="${ROOT}/src/handlers/web/rdp.rs"
SESSIONS_RS="${ROOT}/src/handlers/web/sessions.rs"
ACCESS_HANDLER="${REPO}/vauban-access/src/handlers.rs"
PROXY_SSH="${REPO}/vauban-proxy-ssh/src/main.rs"
PROXY_RDP="${REPO}/vauban-proxy-rdp/src/main.rs"
errors=0

has() { grep -qF -- "$1" <<<"$2"; }

strip_comments() {
    sed -E 's|//.*$||g; s|/\*.*\*/||g' "$1"
}

count_occurrences() {
    # Count non-overlapping fixed-string matches in stripped source.
    local needle="$1"
    local hay="$2"
    local n=0
    local rest="$hay"
    while [[ "$rest" == *"$needle"* ]]; do
        n=$((n + 1))
        rest="${rest#*"$needle"}"
    done
    echo "$n"
}

line_of_first() {
    # 1-based line number of first match of fixed string in file (raw).
    local file="$1"
    local needle="$2"
    grep -nF -- "$needle" "$file" | head -1 | cut -d: -f1 || true
}

check_connect_handler() {
    local label="$1"
    local file="$2"
    if [[ ! -f "$file" ]]; then
        echo "[lint] missing ${file}" >&2
        errors=1
        return
    fi
    local stripped
    stripped="$(strip_comments "$file")"

    # Match a call site, not the word in a comment about the removed path.
    if has 'can_access_asset(' "$stripped"; then
        echo "[lint] ${label}: must NOT call can_access_asset (use early issue_session_token constraints)" >&2
        errors=1
    fi

    local mint_count
    mint_count="$(count_occurrences '.issue_session_token(' "$stripped")"
    if [[ "$mint_count" -ne 1 ]]; then
        echo "[lint] ${label}: expected exactly 1 .issue_session_token(, found ${mint_count}" >&2
        errors=1
    fi

    local mint_line insert_line
    mint_line="$(line_of_first "$file" '.issue_session_token(')"
    insert_line="$(line_of_first "$file" 'insert_into(proxy_sessions')"
    if [[ -z "$mint_line" || -z "$insert_line" ]]; then
        echo "[lint] ${label}: must call issue_session_token and insert_into(proxy_sessions)" >&2
        errors=1
    elif [[ "$mint_line" -ge "$insert_line" ]]; then
        echo "[lint] ${label}: issue_session_token must run BEFORE insert_into(proxy_sessions) (mint=${mint_line} insert=${insert_line})" >&2
        errors=1
    fi
}

check_connect_handler "connect_ssh (${SSH_RS})" "${SSH_RS}"
check_connect_handler "connect_rdp (${RDP_RS})" "${RDP_RS}"

if [[ ! -f "${SESSIONS_RS}" ]]; then
    echo "[lint] missing ${SESSIONS_RS}" >&2
    errors=1
else
    sessions_stripped="$(strip_comments "${SESSIONS_RS}")"
    if ! has 'can_access_asset' "$sessions_stripped"; then
        echo "[lint] sessions.rs submit_access_request path must keep can_access_asset" >&2
        errors=1
    fi
fi

if [[ ! -f "${ACCESS_HANDLER}" ]]; then
    echo "[lint] missing ${ACCESS_HANDLER}" >&2
    errors=1
else
    # Pin that IssueSessionToken success carries constraint fields.
    if ! grep -qF 'AccessResponse::SessionTokenIssued' "${ACCESS_HANDLER}"; then
        echo "[lint] handlers.rs must construct SessionTokenIssued" >&2
        errors=1
    fi
    # Within handle_issue_session_token, require the three constraint fields
    # on the success arm (not only diagnostic's inert false/None).
    fn_start="$(grep -n 'fn handle_issue_session_token' "${ACCESS_HANDLER}" | head -1 | cut -d: -f1 || true)"
    if [[ -z "${fn_start}" ]]; then
        echo "[lint] handle_issue_session_token missing" >&2
        errors=1
    else
        body="$(sed -n "${fn_start},$((fn_start + 120))p" "${ACCESS_HANDLER}")"
        for field in require_mfa require_approval max_session_duration; do
            if ! grep -qF "${field}" <<<"${body}"; then
                echo "[lint] handle_issue_session_token must propagate ${field} into SessionTokenIssued" >&2
                errors=1
            fi
        done
    fi
fi

for proxy in "${PROXY_SSH}" "${PROXY_RDP}"; do
    if [[ ! -f "${proxy}" ]]; then
        echo "[lint] missing ${proxy}" >&2
        errors=1
        continue
    fi
    if ! grep -qF 'AccessGuard::authorize' "${proxy}" && ! grep -qF '.authorize(' "${proxy}"; then
        # AccessGuard may be used as `guard.authorize` — accept either form.
        if ! grep -qE 'authorize\(' "${proxy}"; then
            echo "[lint] ${proxy} must keep AccessGuard authorize (proxy policy eval)" >&2
            errors=1
        fi
    fi
done

# Stronger pin: AccessGuard symbol present in both proxies.
for proxy in "${PROXY_SSH}" "${PROXY_RDP}"; do
    if [[ -f "${proxy}" ]] && ! grep -qF 'AccessGuard' "${proxy}"; then
        echo "[lint] ${proxy} must reference AccessGuard" >&2
        errors=1
    fi
done

if [[ "$errors" -ne 0 ]]; then
    exit 1
fi
echo "[lint] policy eval session-open 3→2 invariants OK"
exit 0
