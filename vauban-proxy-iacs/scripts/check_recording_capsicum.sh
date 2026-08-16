#!/usr/bin/env bash
# vauban-proxy-iacs structural lint for the IACS PCAP recording
# wiring under Capsicum sandboxing.
#
# Invariants enforced:
#   1. The audit IPC is wired BEFORE `capsicum::setup_service_sandbox`
#      (FreeBSD/Capsicum forbids `set_nonblocking` and similar
#      `fcntl` calls post-`cap_enter`, so AsyncIpcChannel must be
#      constructed pre-sandbox).
#   2. The proxy never `drop()`s `audit_channel` mid-runtime (it is
#      the durability backbone of the recording pipeline).
#   3. No `try_send` on the recording channel: a slow audit MUST
#      surface as backpressure on the relay, not silent frame drops.
#   4. No `TcpStream::connect` post-Capsicum (the supervisor brokers
#      every upstream socket via SCM_RIGHTS; direct connect would
#      be killed).
#   5. The `originator_address` / `originator_port` arguments of
#      `channel_open_direct_tcpip` are NOT `_`-prefixed (the
#      synthetic L3/L4 layer in vauban-audit needs them).
#   6. The proxy reads `peer_addr()` of the brokered upstream
#      stream BEFORE splitting into reader/writer (otherwise the
#      address is unrecoverable).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel 2>/dev/null)"; then
    cd "$ROOT"
else
    cd "$SCRIPT_DIR/../.."
fi

MAIN=vauban-proxy-iacs/src/main.rs
SERVER=vauban-proxy-iacs/src/server.rs
RECORDING=vauban-proxy-iacs/src/iacs_recording.rs

for f in "$MAIN" "$SERVER" "$RECORDING"; do
    if [[ ! -f "$f" ]]; then
        echo "ERROR: missing source file $f" >&2
        exit 2
    fi
done

fail=0

# 1. audit_async constructed before Capsicum sandbox.
audit_line=$(grep -n 'let audit_async = if recording_enabled' "$MAIN" \
             | head -n1 | cut -d: -f1)
sandbox_line=$(grep -n 'capsicum::setup_service_sandbox' "$MAIN" \
               | head -n1 | cut -d: -f1)
if [[ -z "$audit_line" || -z "$sandbox_line" ]]; then
    echo "ERROR: could not locate audit_async / sandbox markers in $MAIN" >&2
    fail=1
elif (( audit_line >= sandbox_line )); then
    echo "ERROR: audit_async (line $audit_line) MUST be wired before" \
         "Capsicum sandbox (line $sandbox_line) -- AsyncIpcChannel::new" \
         "performs fcntl which is forbidden post-cap_enter" >&2
    fail=1
fi

# 2. No drop(audit_channel) in main.
if grep -n 'drop(audit_channel)' "$MAIN" >&2; then
    echo "ERROR: drop(audit_channel) found -- the audit IPC must remain" \
         "wired for the lifetime of the proxy" >&2
    fail=1
fi

# 3. No try_send on the recording channel.
if grep -nE '\.try_send\b' "$RECORDING" >&2; then
    echo "ERROR: try_send found in $RECORDING -- audit ack must be" \
         "blocking; try_send would silently drop frames under load" >&2
    fail=1
fi

# 4. No direct TcpStream::connect post-Capsicum sandbox.
sandbox_offset=$(grep -nE '^[[:space:]]*capsicum::setup_service_sandbox' "$MAIN" \
                 | head -n1 | cut -d: -f1 || true)
if [[ -n "$sandbox_offset" ]]; then
    if tail -n +"$sandbox_offset" "$MAIN" | grep -qE 'TcpStream::connect'; then
        echo "ERROR: TcpStream::connect found AFTER Capsicum sandbox" \
             "in $MAIN -- the supervisor must broker every upstream fd" >&2
        fail=1
    fi
fi

# 5. The `direct-tcpip` callback MUST capture originator_address
#    without an `_` prefix (the synth L3/L4 layer needs it for the
#    client-side IP/port of the synthesised TCP segments). Other
#    `channel_open_*` callbacks legitimately keep the `_` prefix
#    because their channels are refused outright.
if ! grep -qE '^\s*originator_address: &str,$' "$SERVER"; then
    echo "ERROR: channel_open_direct_tcpip in $SERVER must accept" \
         "originator_address (no _ prefix) -- the synth L3/L4 layer" \
         "needs it for the client-side IP/port of the TCP segments" >&2
    fail=1
fi

# 6. peer_addr() read before into_split() of upstream_stream.
peer_line=$(grep -n 'upstream_stream$' "$SERVER" \
            | head -n1 | cut -d: -f1 || true)
into_split_line=$(grep -n 'upstream\.into_split' "$SERVER" \
                  | head -n1 | cut -d: -f1 || true)
if [[ -n "$peer_line" && -n "$into_split_line" ]] \
   && (( peer_line >= into_split_line )); then
    echo "ERROR: peer_addr() must be read BEFORE upstream.into_split()" >&2
    fail=1
fi

# 7. AsyncIpcChannel(audit) must NOT appear in main_loop (it must
#    be constructed before the loop, which itself runs in-sandbox).
if awk '/async fn main_loop/{flag=1} flag' "$MAIN" \
       | grep -qE 'AsyncIpcChannel::new\(audit'; then
    echo "ERROR: AsyncIpcChannel::new(audit ...) inside main_loop in $MAIN" \
         "-- must live in main() pre-sandbox" >&2
    fail=1
fi

if [[ $fail -ne 0 ]]; then
    echo "FAIL: vauban-proxy-iacs Capsicum / recording invariants violated." >&2
    exit 1
fi

echo "OK: vauban-proxy-iacs Capsicum + recording invariants hold."
