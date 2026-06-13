#!/usr/bin/env bash
# Standalone bash mirror of the VAU-006 recording-file path pins
# (vauban-supervisor/tests/recording_broker_path_pin_test.rs).
#
# Enforces the invariants behind the fix:
#   INV-2  the path is resolved BEFORE any File::open / File::create /
#          create_dir_all in handle_recording_file_request (fail-closed).
#   INV-3  the handler resolves through
#          shared::recording_paths::resolve_recording_file_target, and no
#          naked Path::new(storage_base).join(relative_path) survives.
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
SHARED="shared/src/recording_paths.rs"
fail=0

err() {
    echo "FAIL: $1" >&2
    fail=1
}

# INV-3 (definition side): the shared seam exists.
if ! grep -q "pub fn resolve_recording_file_target(" "$SHARED"; then
    err "INV-3: shared::recording_paths::resolve_recording_file_target must exist (the single seam)."
fi

# Extract the handler body: from its signature to the next top-level `fn `.
body="$(sed -n '/^fn handle_recording_file_request(/,/^fn [a-z]/p' "$SUP")"

# INV-3: the handler resolves via the shared seam.
if ! grep -q "shared::recording_paths::resolve_recording_file_target" <<<"$body"; then
    err "INV-3: handle_recording_file_request must resolve via resolve_recording_file_target."
fi

# INV-2/INV-3 drift guard: the VAU-006 naked join is gone.
if grep -q "Path::new(storage_base).join(relative_path)" <<<"$body"; then
    err "INV-3: handle_recording_file_request must not join storage_base with the untrusted relative_path (VAU-006 regression)."
fi

# INV-2 pre-syscall order: resolve seam precedes every FS syscall.
resolve_line="$(grep -n "resolve_recording_file_target" <<<"$body" | head -n1 | cut -d: -f1 || true)"
if [ -z "$resolve_line" ]; then
    err "INV-2: resolve_recording_file_target not found in handler body."
else
    for syscall in "File::open" "File::create" "create_dir_all"; do
        sys_line="$(grep -n "$syscall" <<<"$body" | head -n1 | cut -d: -f1 || true)"
        if [ -z "$sys_line" ]; then
            err "INV-2: '$syscall' not found in handler body (unexpected layout)."
        elif [ "$resolve_line" -ge "$sys_line" ]; then
            err "INV-2: path resolution must precede '$syscall' (fail-closed pre-syscall)."
        fi
    done
fi

if [ "$fail" -ne 0 ]; then
    echo "check_recording_broker_path.sh: FAILED" >&2
    exit 1
fi
echo "check_recording_broker_path.sh: OK"
