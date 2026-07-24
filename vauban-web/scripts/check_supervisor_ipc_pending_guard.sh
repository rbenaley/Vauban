#!/usr/bin/env bash
# Lint: SupervisorClient pending maps use PendingGuard / insert_pending.
#
# The sync poll + SCM_RIGHTS thread stays; correlation hygiene must still
# RAII-GC the three pending maps (INV-CORR-1 style).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SUP="${ROOT}/src/ipc/supervisor.rs"

fail=0

if [[ ! -f "${SUP}" ]]; then
    echo "[lint] missing ${SUP}" >&2
    exit 2
fi

for needle in \
    "CorrelatedIpcCore::insert_pending" \
    "pending_tcp_connects" \
    "pending_recording_files" \
    "pending_recording_deletes" \
    "PendingGuard hygiene" \
    "not AsyncFd"
do
    if ! grep -q "${needle}" "${SUP}"; then
        echo "[lint] supervisor.rs must contain '${needle}'" >&2
        fail=1
    fi
done

# Each request_* path must install a guard via insert_pending
for meth in request_tcp_connect request_recording_file request_recording_delete; do
    # Extract a window after the fn and require insert_pending before the
    # next pub async fn / end of impl block is hard in bash; count calls.
    :
done

insert_count="$(grep -c "CorrelatedIpcCore::insert_pending" "${SUP}" || true)"
if [[ "${insert_count}" -lt 3 ]]; then
    echo "[lint] expected >=3 insert_pending calls (one per request_*), found ${insert_count}" >&2
    fail=1
fi

# Forbidden: AsyncFd rewrite in production body (ignore #[cfg(test)] tail)
prod="$(sed '/^#\[cfg(test)\]/,$d' "${SUP}")"
if echo "${prod}" | grep -qE "AsyncFd::|\.process_loop\("; then
    echo "[lint] supervisor.rs must not use AsyncFd / process_loop" >&2
    fail=1
fi

# Manual pending_*.remove in production request paths is forbidden
# (PendingGuard Drop / CorrelatedIpcCore::deliver own GC).
while IFS= read -r hit; do
    if echo "${hit}" | grep -q "pending_tcp_connects\|pending_recording_files\|pending_recording_deletes"; then
        if echo "${hit}" | grep -q "\.remove("; then
            echo "[lint] manual pending map remove (use PendingGuard Drop / deliver): ${hit}" >&2
            fail=1
        fi
    fi
done < <(echo "${prod}" | grep -n "pending_.*\.remove\|\.remove(&request_id)" || true)

if [[ "${fail}" -ne 0 ]]; then
    echo "[lint] check_supervisor_ipc_pending_guard FAILED" >&2
    exit 1
fi

echo "[lint] check_supervisor_ipc_pending_guard OK"
exit 0
