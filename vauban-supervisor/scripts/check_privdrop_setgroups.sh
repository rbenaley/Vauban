#!/usr/bin/env bash
# Standalone bash mirror of the VAU-009 privilege-drop group-purge pins
# (vauban-supervisor/tests/privdrop_pin_test.rs).
#
# Enforces the invariants behind the fix:
#   INV-1   shared::privdrop::drop_privileges purges supplementary groups
#           via setgroups(&[]).
#   INV-2   order setgroups -> setgid -> setuid (purge while still root).
#   INV-3a  spawn_child drops privileges via shared::privdrop::drop_privileges.
#   INV-3b  single door / drift guard: no raw setgroups(/setgid(/setuid(
#           survives in the supervisor main.rs (comments excluded).
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
PRIVDROP="shared/src/privdrop.rs"
fail=0

err() {
    echo "FAIL: $1" >&2
    fail=1
}

# INV-1: the primitive purges supplementary groups (setgroups(0, NULL)).
if ! grep -q "setgroups(0" "$PRIVDROP"; then
    err "INV-1: $PRIVDROP must purge supplementary groups via setgroups(0, NULL)."
fi

# INV-2: setgroups before setgid before setuid (line-number ordering).
groups_line="$(grep -n "setgroups(" "$PRIVDROP" | head -n1 | cut -d: -f1 || true)"
setgid_line="$(grep -n "setgid(" "$PRIVDROP" | head -n1 | cut -d: -f1 || true)"
setuid_line="$(grep -n "setuid(" "$PRIVDROP" | head -n1 | cut -d: -f1 || true)"
if [ -z "$groups_line" ] || [ -z "$setgid_line" ] || [ -z "$setuid_line" ]; then
    err "INV-2: $PRIVDROP must call setgroups, setgid and setuid."
elif ! { [ "$groups_line" -lt "$setgid_line" ] && [ "$setgid_line" -lt "$setuid_line" ]; }; then
    err "INV-2: order must be setgroups($groups_line) -> setgid($setgid_line) -> setuid($setuid_line)."
fi

# INV-3a: the supervisor drops privileges through the primitive seam.
if ! grep -q "shared::privdrop::drop_privileges(" "$SUP"; then
    err "INV-3a: spawn_child must drop privileges via shared::privdrop::drop_privileges."
fi

# INV-3b: drift guard. Strip // line comments, then ensure no raw call.
code_no_comments="$(sed 's://.*$::' "$SUP")"
for forbidden in "setgroups(" "setgid(" "setuid("; do
    if printf '%s' "$code_no_comments" | grep -qF "$forbidden"; then
        err "INV-3b: $SUP must not call '$forbidden' inline; route through shared::privdrop::drop_privileges."
    fi
done

if [ "$fail" -ne 0 ]; then
    echo "check_privdrop_setgroups.sh: FAILED" >&2
    exit 1
fi
echo "check_privdrop_setgroups.sh: OK"
