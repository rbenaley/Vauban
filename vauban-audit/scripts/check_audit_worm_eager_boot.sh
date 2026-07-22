#!/usr/bin/env bash
# Structural lint: WORM segment + signing key must be mandatory at audit
# boot (PAM bastion posture). No VAUBAN_AUDIT_REQUIRED toggle.
#
# Regressions guarded forever:
#
# 1. Missing `open_initial_worm_segment` / not called before `main_loop`.
# 2. Boot continues when key unseal or WORM open fails (BestEffort return).
# 3. `VAUBAN_AUDIT_REQUIRED` env switch reappears.
# 4. Lazy open removed from `handle_audit_event` (defense-in-depth).
#
# Companion of:
#   - vauban-audit/src/main.rs (boot + handle_audit_event)
#   - vauban-audit/tests/worm_eager_boot_*_test.rs
#
# Returns non-zero on the first violation.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MAIN="${ROOT}/src/main.rs"
errors=0

has() { grep -qF -- "$1" <<<"$2"; }

strip_comments() {
    sed -E 's|//.*$||g; s|/\*.*\*/||g' "$1"
}

if [[ ! -f "${MAIN}" ]]; then
    echo "[lint] missing ${MAIN}" >&2
    exit 1
fi
stripped="$(strip_comments "${MAIN}")"

for token in \
    'fn open_initial_worm_segment' \
    'open_initial_worm_segment(' \
    'WORM segment opened at boot' \
    'refusing to start without Ed25519 WORM seals' \
    'refusing to start without durable audit log'
do
    if ! has "${token}" "${stripped}"; then
        echo "[lint] ${MAIN} must contain \`${token}\`" >&2
        errors=1
    fi
done

if has 'VAUBAN_AUDIT_REQUIRED' "${stripped}"; then
    echo "[lint] ${MAIN}: VAUBAN_AUDIT_REQUIRED toggle must stay removed" >&2
    errors=1
fi

if has 'audit_required' "${stripped}"; then
    echo "[lint] ${MAIN}: audit_required field/flag must stay removed" >&2
    errors=1
fi

# Boot call must appear before main_loop invocation in run_service body.
run_start="$(grep -n 'fn run_service' "${MAIN}" | head -1 | cut -d: -f1 || true)"
if [[ -z "${run_start}" ]]; then
    echo "[lint] fn run_service missing" >&2
    errors=1
else
    body="$(sed -n "${run_start},$((run_start + 320))p" "${MAIN}")"
    open_line="$(grep -n 'open_initial_worm_segment(' <<<"${body}" | head -1 | cut -d: -f1 || true)"
    loop_line="$(grep -n 'main_loop(' <<<"${body}" | head -1 | cut -d: -f1 || true)"
    if [[ -z "${open_line}" || -z "${loop_line}" ]]; then
        echo "[lint] run_service must call open_initial_worm_segment and main_loop" >&2
        errors=1
    elif [[ "${open_line}" -ge "${loop_line}" ]]; then
        echo "[lint] open_initial_worm_segment must run BEFORE main_loop" >&2
        errors=1
    fi
fi

fn_start="$(grep -n 'fn handle_audit_event' "${MAIN}" | head -1 | cut -d: -f1 || true)"
if [[ -z "${fn_start}" ]]; then
    echo "[lint] fn handle_audit_event missing" >&2
    errors=1
else
    hbody="$(sed -n "${fn_start},$((fn_start + 80))p" "${MAIN}")"
    if ! grep -qF 'open_initial_worm_segment' <<<"${hbody}"; then
        echo "[lint] handle_audit_event must retain defense-in-depth open_initial_worm_segment" >&2
        errors=1
    fi
fi

if [[ "${errors}" -ne 0 ]]; then
    echo "[lint] check_audit_worm_eager_boot.sh FAILED" >&2
    exit 1
fi

echo "[lint] check_audit_worm_eager_boot.sh OK"
exit 0
