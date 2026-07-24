#!/usr/bin/env bash
# Lint guard: correlated IPC core (INV-CORR-1..5).
#
# Why: architecture review §4.2 / reco §10.7 — seven hand-written
# AsyncFd process_incoming loops drifted (clear_ready races, pending
# GC holes). Migrated peers must drain via CorrelatedIpcCore::process_loop
# (try_io). Until a peer is migrated it may carry
# `// allow-legacy-pump: <reason>`.
#
# The AsyncFd core lives in shared/src/correlated_ipc.rs (0.9.31+);
# vauban-web/src/ipc/correlated.rs is a thin re-export + AppError map.
# SupervisorClient is NOT an AsyncFd peer (PendingGuard hygiene only).
#
# Checks:
#   1. shared correlated_ipc.rs exists with try_io + PendingGuard + process_loop
#   2. clear_ready() only in correlated_ipc.rs OR allow-legacy-pump peers
#   3. each AsyncFd peer has process_loop usage OR allow-legacy-pump
#   4. timeout constants table present (INV-CORR-5)
#   5. no AsyncFd process_loop peer for supervisor.rs

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REPO="$(cd "${ROOT}/.." && pwd)"
CORR="${REPO}/shared/src/correlated_ipc.rs"
WEB_REEXPORT="${ROOT}/src/ipc/correlated.rs"
PEERS=(
    access.rs
    auth.rs
    audit.rs
    vault.rs
    proxy_ssh.rs
    proxy_rdp.rs
    proxy_iacs.rs
)

fail=0

if [[ ! -f "${CORR}" ]]; then
    echo "[lint] missing ${CORR}" >&2
    exit 2
fi

if [[ ! -f "${WEB_REEXPORT}" ]]; then
    echo "[lint] missing web re-export ${WEB_REEXPORT}" >&2
    fail=1
fi

if [[ -f "${WEB_REEXPORT}" ]] && ! grep -q "shared::correlated_ipc" "${WEB_REEXPORT}"; then
    echo "[lint] ${WEB_REEXPORT} must re-export shared::correlated_ipc" >&2
    fail=1
fi

# ---- 1. Core must exist with the load-bearing symbols --------------------
for needle in "try_io" "PendingGuard" "fn process_loop" "INV-CORR-5"; do
    if ! grep -q "${needle}" "${CORR}"; then
        echo "[lint] correlated_ipc.rs must contain '${needle}'" >&2
        fail=1
    fi
done

# INV-CORR-5 timeout table (documentation pins)
for needle in "30 s" "10 s" "5 s" "no timeout"; do
    if ! grep -q "${needle}" "${CORR}"; then
        echo "[lint] correlated_ipc.rs INV-CORR-5 table missing '${needle}'" >&2
        fail=1
    fi
done

# ---- 2 / 3. Per-peer migration status ------------------------------------
for peer in "${PEERS[@]}"; do
    f="${ROOT}/src/ipc/${peer}"
    if [[ ! -f "${f}" ]]; then
        echo "[lint] missing peer ${f}" >&2
        fail=1
        continue
    fi

    has_legacy=0
    if grep -q "allow-legacy-pump" "${f}"; then
        has_legacy=1
    fi

    has_core=0
    if grep -qE "process_loop\(|core\.process_loop|CorrelatedIpcCore" "${f}"; then
        # Require actual process_loop call for migrated peers (not just import)
        if grep -qE "\.process_loop\(|process_blocking_on\(" "${f}"; then
            has_core=1
        fi
    fi

    if [[ "${has_legacy}" -eq 0 && "${has_core}" -eq 0 ]]; then
        echo "[lint] ${peer}: must call process_loop/process_blocking_on or carry // allow-legacy-pump" >&2
        fail=1
    fi

    # clear_ready forbidden outside core unless legacy allowed
    if grep -n "clear_ready" "${f}" >/dev/null 2>&1; then
        if [[ "${has_legacy}" -eq 0 ]]; then
            echo "[lint] ${peer}: clear_ready() forbidden after migration (use core try_io)" >&2
            grep -n "clear_ready" "${f}" >&2 || true
            fail=1
        fi
    fi
done

# Supervisor must NOT be an AsyncFd process_loop peer (ignore #[cfg(test)] tail)
SUP="${ROOT}/src/ipc/supervisor.rs"
if [[ -f "${SUP}" ]]; then
    prod="$(sed '/^#\[cfg(test)\]/,$d' "${SUP}")"
    if echo "${prod}" | grep -qE "\.process_loop\(|AsyncFd::"; then
        echo "[lint] supervisor.rs must NOT use AsyncFd process_loop (PendingGuard only)" >&2
        fail=1
    fi
fi

# clear_ready must not appear in web ipc/ except allow-legacy-pump peers
while IFS= read -r hit; do
    file="${hit%%:*}"
    base="$(basename "${file}")"
    if [[ "${base}" == "correlated.rs" ]]; then
        continue
    fi
    if grep -q "allow-legacy-pump" "${file}"; then
        continue
    fi
    echo "[lint] clear_ready in web ipc without allow-legacy-pump: ${hit}" >&2
    fail=1
done < <(grep -rn "clear_ready" "${ROOT}/src/ipc" --include='*.rs' || true)

# clear_ready in shared may only appear inside correlated_ipc try_io path
# (or comments). access_guard must not use clear_ready after RbacClient migration.
AG="${REPO}/shared/src/access_guard.rs"
if [[ -f "${AG}" ]] && grep -n "clear_ready" "${AG}" >/dev/null 2>&1; then
    echo "[lint] access_guard.rs: clear_ready forbidden (RbacClient must use try_io)" >&2
    grep -n "clear_ready" "${AG}" >&2 || true
    fail=1
fi

if [[ "${fail}" -ne 0 ]]; then
    echo "[lint] check_ipc_correlated_core FAILED" >&2
    exit 1
fi

echo "[lint] check_ipc_correlated_core OK"
exit 0
