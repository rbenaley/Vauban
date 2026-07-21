#!/usr/bin/env bash
# Structural lint: MFA fail-closed AuditAck must not be HOL-blocked by
# supervisor broker waits or IACS gzip on the audit main loop.
#
# Regressions guarded forever:
#
# 1. Infinite `channel.recv()` waits on supervisor broker replies
#    (pre-fix: silent / version-skewed supervisor wedges audit;
#    web MFA then hits `audit ack timed out` at 5 s).
#
# 2. `AuditAck` emitted AFTER `rotate_segment` (rotation blocks on the
#    same broker and delayed the durable ack past the web budget).
#
# 3. Web AuditEvents not priority-drained (`drain_web_audit_channel`)
#    so IACS ChannelEnd gzip starves MFA criticals.
#
# 4. Budget drift: broker timeout must stay strictly below web
#    CRITICAL_ACK_TIMEOUT (pinned in mfa_hol_budget.rs + ipc/audit.rs).
#
# Companion of:
#   - vauban-audit/src/mfa_hol_budget.rs
#   - vauban-audit/src/main.rs (timed broker + drain + ack-before-rotate)
#   - vauban-web/src/ipc/audit.rs (CRITICAL_ACK_TIMEOUT_SECS)
#   - vauban-web/src/handlers/auth.rs (emit_audit_critical before JWT mint)
#
# Returns non-zero on the first violation.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REPO="$(cd "${ROOT}/.." && pwd)"

errors=0

MAIN="${ROOT}/src/main.rs"
BUDGET="${ROOT}/src/mfa_hol_budget.rs"
WEB_AUDIT="${REPO}/vauban-web/src/ipc/audit.rs"
WEB_AUTH="${REPO}/vauban-web/src/handlers/auth.rs"

has() { grep -qF -- "$1" <<<"$2"; }

strip_comments() { sed 's|//.*$||' "$1"; }

# ---- 1. Budget module ----------------------------------------------------
if [[ ! -f "${BUDGET}" ]]; then
    echo "[lint] missing ${BUDGET}" >&2
    exit 1
fi
stripped_budget="$(strip_comments "${BUDGET}")"

for token in \
    'SUPERVISOR_BROKER_TIMEOUT_SECS' \
    'WEB_CRITICAL_ACK_TIMEOUT_SECS' \
    'fn broker_timeout_fits_under_critical_ack' \
    'fn production_broker_budget_is_safe'
do
    if ! has "${token}" "${stripped_budget}"; then
        echo "[lint] ${BUDGET} must define \`${token}\`" >&2
        errors=1
    fi
done

if ! grep -qE 'SUPERVISOR_BROKER_TIMEOUT_SECS:\s*u64\s*=\s*2' "${BUDGET}"; then
    echo "[lint] SUPERVISOR_BROKER_TIMEOUT_SECS must remain 2 (below web 5s ACK budget)" >&2
    errors=1
fi
if ! grep -qE 'WEB_CRITICAL_ACK_TIMEOUT_SECS:\s*u64\s*=\s*5' "${BUDGET}"; then
    echo "[lint] WEB_CRITICAL_ACK_TIMEOUT_SECS must remain 5 (mirror of web CRITICAL_ACK)" >&2
    errors=1
fi

# ---- 2. main.rs timed broker + priority drain + ack-before-rotate --------
if [[ ! -f "${MAIN}" ]]; then
    echo "[lint] missing ${MAIN}" >&2
    exit 1
fi
stripped_main="$(strip_comments "${MAIN}")"

for token in \
    'SUPERVISOR_BROKER_TIMEOUT' \
    'fn recv_from_supervisor_until' \
    'fn recv_fd_timed' \
    'fn drain_web_audit_channel' \
    'drain_web_audit_channel('
do
    if ! has "${token}" "${stripped_main}"; then
        echo "[lint] ${MAIN} must contain \`${token}\`" >&2
        errors=1
    fi
done

# Ack before rotate inside handle_audit_event.
fn_start="$(grep -n 'fn handle_audit_event' "${MAIN}" | head -1 | cut -d: -f1 || true)"
if [[ -z "${fn_start}" ]]; then
    echo "[lint] ${MAIN}: fn handle_audit_event missing" >&2
    errors=1
else
    # Take a window of the function body (next ~120 lines).
    body="$(sed -n "${fn_start},$((fn_start + 120))p" "${MAIN}")"
    ack_line="$(grep -n 'Message::AuditAck' <<<"${body}" | head -1 | cut -d: -f1 || true)"
    rotate_line="$(grep -n 'rotate_segment(' <<<"${body}" | head -1 | cut -d: -f1 || true)"
    if [[ -z "${ack_line}" || -z "${rotate_line}" ]]; then
        echo "[lint] handle_audit_event must send AuditAck and call rotate_segment" >&2
        errors=1
    elif [[ "${ack_line}" -ge "${rotate_line}" ]]; then
        echo "[lint] AuditAck must be sent BEFORE rotate_segment (HOL / MFA)" >&2
        errors=1
    fi
fi

# Infinite blocking recv loops in broker helpers are forbidden (must use
# the timed helper). Allow Ping/Pong construction elsewhere.
if grep -n 'fn request_audit_log_file_from_supervisor\|fn request_file_from_supervisor\|fn request_unlink_from_supervisor' -A 80 "${MAIN}" \
    | grep -qE 'channel\.recv\(\)'; then
    # Narrower check: the three request_* bodies must call recv_from_supervisor_until.
    for fn in request_audit_log_file_from_supervisor request_file_from_supervisor request_unlink_from_supervisor; do
        if ! grep -A 60 "fn ${fn}" "${MAIN}" | grep -q 'recv_from_supervisor_until'; then
            echo "[lint] ${fn} must wait via recv_from_supervisor_until (timed)" >&2
            errors=1
        fi
    done
fi

# ---- 3. Web CRITICAL_ACK + MFA fail-closed order -------------------------
if [[ ! -f "${WEB_AUDIT}" ]]; then
    echo "[lint] missing ${WEB_AUDIT}" >&2
    errors=1
else
    if ! grep -qE 'CRITICAL_ACK_TIMEOUT_SECS:\s*u64\s*=\s*5' "${WEB_AUDIT}"; then
        echo "[lint] ${WEB_AUDIT}: CRITICAL_ACK_TIMEOUT_SECS must be 5" >&2
        errors=1
    fi
    if ! grep -q 'audit ack timed out' "${WEB_AUDIT}"; then
        echo "[lint] ${WEB_AUDIT}: must surface \"audit ack timed out\"" >&2
        errors=1
    fi
fi

if [[ ! -f "${WEB_AUTH}" ]]; then
    echo "[lint] missing ${WEB_AUTH}" >&2
    errors=1
else
    # MfaChallengePassed must be inside an emit_audit_critical call that
    # completes before the JWT mint (`true, // mfa_verified`) on that path.
    mfa_line="$(grep -n 'AuditEventType::MfaChallengePassed' "${WEB_AUTH}" | head -1 | cut -d: -f1 || true)"
    if [[ -z "${mfa_line}" ]]; then
        echo "[lint] ${WEB_AUTH}: MfaChallengePassed marker missing" >&2
        errors=1
    else
        mint_line="$(awk -v start="${mfa_line}" '
            NR > start && /true, \/\/ mfa_verified/ { print NR; exit }
        ' "${WEB_AUTH}" || true)"
        # Look back a few lines: `emit_audit_critical(` precedes the variant.
        lookback_start=$((mfa_line > 15 ? mfa_line - 15 : 1))
        preamble="$(sed -n "${lookback_start},${mfa_line}p" "${WEB_AUTH}")"
        if [[ -z "${mint_line}" ]]; then
            echo "[lint] ${WEB_AUTH}: no mfa_verified mint after MfaChallengePassed" >&2
            errors=1
        elif ! grep -q 'emit_audit_critical' <<<"${preamble}"; then
            echo "[lint] ${WEB_AUTH}: MfaChallengePassed must be emitted via emit_audit_critical" >&2
            errors=1
        elif [[ "${mfa_line}" -ge "${mint_line}" ]]; then
            echo "[lint] ${WEB_AUTH}: MfaChallengePassed must be audited before mfa_verified mint" >&2
            errors=1
        fi
    fi
    if ! grep -q 'audit emit failed' "${WEB_AUTH}"; then
        echo "[lint] ${WEB_AUTH}: MFA critical failure must map to \"audit emit failed\"" >&2
        errors=1
    fi
fi

if [[ "${errors}" -ne 0 ]]; then
    echo "[lint] check_audit_mfa_hol.sh FAILED" >&2
    exit 1
fi

echo "[lint] check_audit_mfa_hol.sh OK"
exit 0
