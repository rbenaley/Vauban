#!/usr/bin/env bash
# Proxies must treat a dead web IPC pipe as sticky EOF + exit 100,
# never as a log-and-spin "Web connection closed" loop.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
errors=0

for crate in vauban-proxy-rdp vauban-proxy-ssh; do
    ipc="${ROOT}/${crate}/src/ipc.rs"
    main="${ROOT}/${crate}/src/main.rs"
    if [[ ! -f "${ipc}" || ! -f "${main}" ]]; then
        echo "[lint] missing ${crate} sources" >&2
        errors=1
        continue
    fi
    # Pin tests mention the forbidden literal; inspect production source only.
    prod_main=$(awk 'BEGIN{p=1} /^#\[cfg\(test\)\]/{p=0} p' "${main}")
    prod_ipc=$(awk 'BEGIN{p=1} /^#\[cfg\(test\)\]/{p=0} p' "${ipc}")
    if printf '%s\n' "${prod_main}" "${prod_ipc}" | grep -n 'Web connection closed'; then
        echo "[lint] ${crate}: forbidden literal 'Web connection closed'" >&2
        errors=1
    fi
    if ! grep -q 'closed: AtomicBool' "${ipc}"; then
        echo "[lint] ${crate}: ipc.rs must track sticky EOF with AtomicBool" >&2
        errors=1
    fi
    if ! grep -q 'clear_ready()' "${ipc}"; then
        echo "[lint] ${crate}: recv must clear_ready on EOF" >&2
        errors=1
    fi
    if ! grep -q 'return Ok(ServiceExit::RespawnRequested)' "${main}"; then
        echo "[lint] ${crate}: web EOF must return ServiceExit::RespawnRequested" >&2
        errors=1
    fi
    if ! grep -q 'Web IPC pipe closed, exiting for linked respawn' "${main}"; then
        echo "[lint] ${crate}: missing linked-respawn log" >&2
        errors=1
    fi
done

if [[ "${errors}" -ne 0 ]]; then
    exit 1
fi
echo "check_ipc_eof_handling: ok"
