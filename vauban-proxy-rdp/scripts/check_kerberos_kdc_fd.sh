#!/usr/bin/env bash
# Structural lint: Kerberos KDC path must be SCM_RIGHTS FD lease + local I/O,
# not an in-band payload relay through the supervisor.
# Uses grep (not rg) so cargo-test sandboxes without ripgrep in PATH still pass.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="${ROOT}/src"
REPO="$(cd "${ROOT}/.." && pwd)"
SUP="${REPO}/vauban-supervisor/src/main.rs"
errors=0

fail() {
    echo "[lint] $*" >&2
    errors=1
}

if ! grep -Eq 'KerberosKdcRequest' "${SRC}/session.rs"; then
    fail "proxy-rdp must send KerberosKdcRequest to lease a KDC FD"
fi

if ! grep -Eq 'recv_fd_timed' "${SRC}/main.rs"; then
    fail "proxy-rdp main_loop must recv_fd_timed for KDC (and recording) leases"
fi

if ! grep -Eq 'KerberosKdcResponse' "${SRC}/main.rs"; then
    fail "proxy-rdp main_loop must demux KerberosKdcResponse"
fi

if ! grep -Eq 'kdc_framed_round_trip|MAX_KDC_REPLY' "${SRC}/session.rs"; then
    fail "proxy-rdp must own framed KDC I/O (kdc_framed_round_trip / MAX_KDC_REPLY)"
fi

# Supervisor broker: send_fd, no payload write_all on the KDC handler.
if ! grep -Eq 'fn handle_kerberos_kdc_request' "${SUP}"; then
    fail "supervisor must expose handle_kerberos_kdc_request"
fi

handler="$(awk '
  /^fn handle_kerberos_kdc_request\(/ { capture=1 }
  capture { print }
  capture && /^fn handle_recording_file_request\(/ { exit }
' "${SUP}")"
if ! printf '%s' "${handler}" | grep -Eq 'send_fd\('; then
    fail "supervisor KDC handler must send_fd the connected socket"
fi
if printf '%s' "${handler}" | grep -Eq 'write_all\(|read_exact\('; then
    fail "supervisor KDC handler must not perform Kerberos payload I/O"
fi
if ! printf '%s' "${handler}" | grep -Eq 'proxy_rdp'; then
    fail "supervisor KDC handler must restrict callers to proxy_rdp"
fi

# Hot path must not treat response.data as KDC payload.
kdc_arm="$(awk '
  /Message::KerberosKdcResponse/ { capture=1 }
  capture { print; n++ }
  capture && n > 25 { exit }
' "${SRC}/main.rs")"
if printf '%s' "${kdc_arm}" | grep -Eq 'into_inner\(|data\.as_slice'; then
    fail "KerberosKdcResponse handler must not consume response.data as KDC payload"
fi

if [[ "${errors}" -ne 0 ]]; then
    exit 1
fi
echo "[lint] kerberos KDC FD invariants OK"
