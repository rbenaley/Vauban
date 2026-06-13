#!/usr/bin/env bash
# Standalone bash mirror of the VAU-005 IPC FD cloisonnement pins
# (vauban-supervisor/tests/ipc_fd_hygiene_pin_test.rs).
#
# Enforces the four invariants behind the fix:
#   INV-1  shared::ipc::IpcChannel::pair() stamps FD_CLOEXEC on the pipe ends.
#   INV-2  shared::ipc::clear_cloexec is the SINGLE door: no raw
#          F_SETFD(FdFlag::empty()) lives in the supervisor.
#   INV-3  spawn_child de-CLOEXECs the supervisor channel + this service's
#          topology pipe ends (outgoing + incoming) via the single door.
#   ---    exactly one fork()/execv( surface, all through spawn_child.
#
# Run before `cargo test`.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel 2>/dev/null)"; then
    cd "$ROOT"
else
    cd "$SCRIPT_DIR/../.."
fi

SUP="vauban-supervisor/src/main.rs"
IPC="shared/src/ipc.rs"
fail=0

err() {
    echo "FAIL: $1" >&2
    fail=1
}

# INV-1
if ! grep -q "F_SETFD(FdFlag::FD_CLOEXEC)" "$IPC"; then
    err "INV-1: $IPC must set FD_CLOEXEC on the pipe ends in pair()."
fi

# INV-2 (single door, drift guard)
if grep -q "F_SETFD(FdFlag::empty())" "$SUP"; then
    err "INV-2: $SUP must not clear FD_CLOEXEC inline; route through shared::ipc::clear_cloexec."
fi
if ! grep -q "pub fn clear_cloexec(" "$IPC"; then
    err "INV-2: shared::ipc::clear_cloexec must exist (the single door)."
fi

# INV-3
if ! grep -q "for fd in \[read_fd, write_fd\]" "$SUP"; then
    err "INV-3: spawn_child must de-CLOEXEC the supervisor channel (read_fd + write_fd)."
fi
if ! grep -q "pipes.outgoing.iter().chain(pipes.incoming.iter())" "$SUP"; then
    err "INV-3: spawn_child must iterate outgoing AND incoming topology pipe ends."
fi
if ! grep -q "shared::ipc::clear_cloexec" "$SUP"; then
    err "INV-3: spawn_child must use the single door shared::ipc::clear_cloexec."
fi

# Exhaustive fork/execv surface
fork_count="$(grep -c "unsafe { fork() }" "$SUP" || true)"
if [ "$fork_count" != "1" ]; then
    err "Expected exactly one 'unsafe { fork() }' in $SUP, found $fork_count."
fi
execv_count="$(grep -c "execv(&c_path" "$SUP" || true)"
if [ "$execv_count" != "1" ]; then
    err "Expected exactly one 'execv(&c_path ...)' in $SUP, found $execv_count."
fi

if [ "$fail" -ne 0 ]; then
    echo "check_ipc_fd_cloexec.sh: FAILED" >&2
    exit 1
fi
echo "check_ipc_fd_cloexec.sh: OK"
