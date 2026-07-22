#!/usr/bin/env bash
# Structural lint: IACS ChannelEnd gzip CPU must stay off the audit
# main poll loop (post-0.9.24 HOL residual).
#
# Regressions guarded forever:
#
# 1. `gzip_channel_pcap_on_fds` / `GzEncoder` inside
#    `handle_iacs_recording_message` (sync CPU on the poll thread).
#
# 2. ChannelEnd not enqueueing `GzipCpuJob` / main not draining
#    completions via wakeup pipe.
#
# 3. Worker module touching supervisor IPC (`IpcChannel`,
#    `request_file`, `request_unlink`).
#
# 4. Supervisor broker still used for dst open + raw unlink only
#    (`SUPERVISOR_BROKER` / timed helpers remain in main).
#
# Companion of:
#   - vauban-audit/src/iacs_gzip_worker.rs
#   - vauban-audit/src/main.rs (enqueue + drain_gzip_completions)
#   - vauban-audit/tests/iacs_gzip_offthread_*_test.rs
#
# Returns non-zero on the first violation.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

errors=0

MAIN="${ROOT}/src/main.rs"
WORKER="${ROOT}/src/iacs_gzip_worker.rs"

has() { grep -qF -- "$1" <<<"$2"; }

strip_comments() {
    # Drop // line comments and /* */ blocks for coarse token search.
    sed -E 's|//.*$||g; s|/\*.*\*/||g' "$1"
}

if [[ ! -f "${MAIN}" ]]; then
    echo "[lint] missing ${MAIN}" >&2
    exit 1
fi
if [[ ! -f "${WORKER}" ]]; then
    echo "[lint] missing ${WORKER}" >&2
    exit 1
fi

stripped_main="$(strip_comments "${MAIN}")"
stripped_worker="$(strip_comments "${WORKER}")"

for token in \
    'fn enqueue_iacs_gzip_job' \
    'fn drain_gzip_completions' \
    'enqueue_iacs_gzip_job(' \
    'drain_gzip_completions(' \
    'GzipCpuJob' \
    'spawn_gzip_worker' \
    'SUPERVISOR_BROKER' \
    'request_file_from_supervisor' \
    'request_unlink_from_supervisor'
do
    if ! has "${token}" "${stripped_main}"; then
        echo "[lint] ${MAIN} must contain \`${token}\`" >&2
        errors=1
    fi
done

if has 'gzip_channel_and_unlink' "${stripped_main}"; then
    echo "[lint] ${MAIN}: sync gzip_channel_and_unlink must stay retired" >&2
    errors=1
fi

# No CPU gzip / GzEncoder inside handle_iacs_recording_message.
fn_start="$(grep -n 'fn handle_iacs_recording_message' "${MAIN}" | head -1 | cut -d: -f1 || true)"
if [[ -z "${fn_start}" ]]; then
    echo "[lint] ${MAIN}: fn handle_iacs_recording_message missing" >&2
    errors=1
else
    # Window covering ChannelEnd + SessionEnd arms (~200 lines).
    body="$(sed -n "${fn_start},$((fn_start + 220))p" "${MAIN}")"
    if grep -qF 'gzip_channel_pcap_on_fds' <<<"${body}"; then
        echo "[lint] handle_iacs_recording_message must not call gzip_channel_pcap_on_fds" >&2
        errors=1
    fi
    if grep -qF 'GzEncoder' <<<"${body}"; then
        echo "[lint] handle_iacs_recording_message must not construct GzEncoder" >&2
        errors=1
    fi
    if ! grep -qF 'enqueue_iacs_gzip_job' <<<"${body}"; then
        echo "[lint] handle_iacs_recording_message must enqueue GzipCpuJob" >&2
        errors=1
    fi
fi

for forbidden in \
    'use shared::ipc' \
    'IpcChannel::' \
    'request_file_from_supervisor' \
    'request_unlink_from_supervisor' \
    'SUPERVISOR_BROKER'
do
    if has "${forbidden}" "${stripped_worker}"; then
        echo "[lint] ${WORKER} must not contain \`${forbidden}\` (CPU-only worker)" >&2
        errors=1
    fi
done

for token in 'fn run_gzip_cpu' 'fn spawn_gzip_worker' 'gzip_channel_pcap_on_fds' 'PendingGzipTracker'; do
    if ! has "${token}" "${stripped_worker}"; then
        echo "[lint] ${WORKER} must contain \`${token}\`" >&2
        errors=1
    fi
done

if [[ "${errors}" -ne 0 ]]; then
    echo "[lint] check_iacs_gzip_offthread.sh FAILED" >&2
    exit 1
fi

echo "[lint] check_iacs_gzip_offthread.sh OK"
exit 0
