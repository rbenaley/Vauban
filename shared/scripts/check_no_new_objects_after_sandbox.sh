#!/usr/bin/env bash
# Standalone mirror of the `no_direct_tcp_after_sandbox_gate` /
# `sandbox_primitives_only_under_sandbox_module` Rust pins
# (shared/tests/sandbox_invariants_test.rs).
#
# Enforces, for every de-privileged service:
#   1. No raw `TcpStream::connect` / `TcpListener::bind` AFTER the
#      `setup_service_sandbox*` gate in main.rs (the supervisor brokers
#      every upstream fd via SCM_RIGHTS). Exemption: a line annotated
#      `// allow-post-sandbox: <reason>`.
#   2. The OS sandbox primitives (pledge/unveil/landlock/seccompiler/
#      restrict_self/enter_capability_mode) live ONLY under
#      shared/src/sandbox/ -- no service reaches for them directly.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel 2>/dev/null)"; then
    cd "$ROOT"
else
    cd "$SCRIPT_DIR/../.."
fi

RAW_FD_SERVICES=(
    vauban-auth
    vauban-vault
    vauban-access
    vauban-audit
    vauban-proxy-ssh
    vauban-proxy-iacs
    vauban-proxy-rdp
)
ALL_SERVICES=("${RAW_FD_SERVICES[@]}" vauban-web)

fail=0

# 1. No raw TcpStream::connect / TcpListener::bind after the sandbox gate.
for svc in "${RAW_FD_SERVICES[@]}"; do
    main="$svc/src/main.rs"
    [[ -f "$main" ]] || { echo "ERROR: missing $main" >&2; fail=1; continue; }
    gate_line=$(grep -nE 'setup_service_sandbox' "$main" | head -n1 | cut -d: -f1)
    if [[ -z "$gate_line" ]]; then
        echo "ERROR: $main does not call setup_service_sandbox*" >&2
        fail=1
        continue
    fi
    if tail -n +"$gate_line" "$main" \
        | grep -nE 'TcpStream::connect|TcpListener::bind' \
        | grep -vF '// allow-post-sandbox' >/dev/null; then
        echo "ERROR: $main: raw TcpStream::connect / TcpListener::bind found" \
             "AFTER the sandbox gate (line $gate_line). The supervisor must" \
             "broker every socket via SCM_RIGHTS. Annotate a justified" \
             "exception with '// allow-post-sandbox: <reason>'." >&2
        fail=1
    fi
done

# 2. Sandbox primitives only under shared/src/sandbox/.
PRIMS='pledge\(|unveil\(|landlock::|seccompiler::|restrict_self\(|enter_capability_mode\('
for svc in "${ALL_SERVICES[@]}"; do
    main="$svc/src/main.rs"
    [[ -f "$main" ]] || continue
    if grep -nE "$PRIMS" "$main" >/dev/null; then
        echo "ERROR: $main calls an OS sandbox primitive directly --" \
             "route it through shared::sandbox." >&2
        fail=1
    fi
done

if [[ $fail -ne 0 ]]; then
    echo "FAIL: sandbox gate invariants violated." >&2
    exit 1
fi

echo "OK: no new objects after sandbox; primitives confined to shared/src/sandbox/."
