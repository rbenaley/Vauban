#!/usr/bin/env bash
# check_iacs_proxy_no_shell.sh
#
# Defence-in-depth lint for the privileged-separated IACS sshd
# (vauban-proxy-iacs/src/server.rs). The russh `Handler` MUST
# refuse every channel type other than `direct-tcpip` to the
# per-session pinned target. The `Handler` trait has many opt-in
# methods (`shell_request`, `exec_request`, `subsystem_request`,
# `pty_request`, `tcpip_forward`, `streamlocal_forward`, ...);
# accidentally implementing any of them with a permissive return
# would be a critical regression with no other lint to catch it.
#
# This script greps for any source line in the IACS handler module
# that looks like an "allow" path for the forbidden surfaces:
#
#   * `Ok(true)`  inside a `*_forward*` or `channel_open_session`
#                 / `channel_open_x11` / `channel_open_forwarded_tcpip`
#                 / `channel_open_direct_streamlocal` method;
#   * `channel_success(channel)` inside any of `pty_request`,
#                 `shell_request`, `exec_request`, `subsystem_request`,
#                 `agent_request`.
#
# The only legitimate `Ok(true)` is inside `channel_open_direct_tcpip`
# (and only AFTER target validation + auth state check). The lint
# allowlists that single function explicitly so a refactor that
# accidentally widens the surface is caught immediately.
#
# Pinned by:
#   - vauban-proxy-iacs/tests/iacs_server_handshake_test.rs
#     (runtime adversarial suite)
#   - this lint runs in CI before `cargo test` (cheap, ~50ms)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
HANDLER="$REPO_ROOT/vauban-proxy-iacs/src/server.rs"

if [[ ! -f "$HANDLER" ]]; then
    echo "FAIL: $HANDLER not found" >&2
    exit 1
fi

fail=0

# --- Forbidden: any *_forward* method returning Ok(true) ----------
forbidden_forward=$(grep -nE '^\s*async fn (tcpip_forward|cancel_tcpip_forward|streamlocal_forward|cancel_streamlocal_forward)' "$HANDLER" || true)
if [[ -n "$forbidden_forward" ]]; then
    while IFS= read -r line; do
        ln="${line%%:*}"
        end=$((ln + 30))
        body=$(sed -n "${ln},${end}p" "$HANDLER")
        if echo "$body" | grep -qE 'Ok\(true\)'; then
            echo "FAIL: $HANDLER: forward handler at line $ln returns Ok(true)" >&2
            fail=1
        fi
    done <<< "$forbidden_forward"
fi

# --- Forbidden: channel_open_{session,x11,forwarded_tcpip,direct_streamlocal} returning Ok(true)
for fn in channel_open_session channel_open_x11 channel_open_forwarded_tcpip channel_open_direct_streamlocal; do
    matches=$(grep -nE "^\s*async fn ${fn}" "$HANDLER" || true)
    if [[ -n "$matches" ]]; then
        while IFS= read -r line; do
            ln="${line%%:*}"
            end=$((ln + 30))
            body=$(sed -n "${ln},${end}p" "$HANDLER")
            if echo "$body" | grep -qE 'Ok\(true\)'; then
                echo "FAIL: $HANDLER: ${fn} at line $ln returns Ok(true)" >&2
                fail=1
            fi
        done <<< "$matches"
    fi
done

# --- Forbidden: channel_success inside session-channel commands ---
for fn in pty_request shell_request exec_request subsystem_request agent_request; do
    matches=$(grep -nE "^\s*async fn ${fn}" "$HANDLER" || true)
    if [[ -n "$matches" ]]; then
        while IFS= read -r line; do
            ln="${line%%:*}"
            end=$((ln + 30))
            body=$(sed -n "${ln},${end}p" "$HANDLER")
            if echo "$body" | grep -q 'channel_success'; then
                echo "FAIL: $HANDLER: ${fn} at line $ln calls channel_success (should call channel_failure)" >&2
                fail=1
            fi
        done <<< "$matches"
    fi
done

# --- Required: every refusal helper must call channel_failure ----
for fn in pty_request shell_request exec_request subsystem_request; do
    matches=$(grep -nE "^\s*async fn ${fn}" "$HANDLER" || true)
    if [[ -n "$matches" ]]; then
        while IFS= read -r line; do
            ln="${line%%:*}"
            end=$((ln + 30))
            body=$(sed -n "${ln},${end}p" "$HANDLER")
            if ! echo "$body" | grep -q 'channel_failure'; then
                echo "FAIL: $HANDLER: ${fn} at line $ln does not call channel_failure" >&2
                fail=1
            fi
        done <<< "$matches"
    fi
done

# --- Required: channel_open_direct_tcpip MUST validate target ----
if ! grep -q 'validate_target' "$HANDLER"; then
    echo "FAIL: $HANDLER: channel_open_direct_tcpip does not call validate_target()" >&2
    fail=1
fi

# --- Required: auth_password and auth_keyboard_interactive both
#               return Auth::reject() (the trait's default already
#               does so; we re-implement explicitly to make the
#               refusal grep-visible AND robust to russh trait
#               default changes).
for fn in auth_password auth_keyboard_interactive; do
    matches=$(grep -nE "^\s*async fn ${fn}" "$HANDLER" || true)
    if [[ -z "$matches" ]]; then
        echo "FAIL: $HANDLER: ${fn} not explicitly refused (trait default may change)" >&2
        fail=1
        continue
    fi
    while IFS= read -r line; do
        ln="${line%%:*}"
        end=$((ln + 15))
        body=$(sed -n "${ln},${end}p" "$HANDLER")
        if ! echo "$body" | grep -q 'Auth::reject'; then
            echo "FAIL: $HANDLER: ${fn} at line $ln does not return Auth::reject()" >&2
            fail=1
        fi
    done <<< "$matches"
done

if [[ $fail -ne 0 ]]; then
    echo "" >&2
    echo "FAIL: iacs_tunnel handler refusal surface check failed -- see errors above" >&2
    exit 1
fi

echo "OK: vauban-proxy-iacs handler rejects all non-direct-tcpip surfaces"
