#!/usr/bin/env bash
# Issue #34 -- structural lint: pin the SSH host-key end-to-end paths.
#
# Two regressions we are guarding against forever:
#
# 1. `verify_ssh_host_key` returning the GREEN "SSH Host Key Verified"
#    fragment from a fallback / Err / proxy-unavailable branch
#    (silent green). Pre-fix any IPC failure in the verify path
#    (proxy down, AccessGuard refused the session-token mint, network
#    down) collapsed to the green fragment and operators reading the
#    admin /assets/manage/{uuid} detail page were silently told the
#    server was fine. The fix introduces an AMBER "Could not verify"
#    fragment for those branches; this lint refuses any code path
#    where the green fragment include sits inside an `Err(...) =>`
#    or `None =>` arm.
#
# 2. `connect_ssh` opening a session when no host key is pinned or
#    when the mismatch flag is set (TOFU window indefinite). The fix
#    is a strict pre-flight gate that refuses with one of two
#    user-visible messages. This lint asserts both literals are
#    present in `connect_ssh`. Removing them re-opens the regression.
#
# Companion of:
#   - vauban-web/tests/web/ssh_host_key_no_silent_green_test.rs
#     (source-grep pin tests during `cargo test`)
#   - vauban-web/tests/web/ssh_host_key_e2e_test.rs (E2E coverage,
#     real Axum router + DB)
#   - vauban-proxy-ssh/src/session.rs::host_key_behavioural_tests
#     (in-process russh server fixture covering the proxy layer).
#
# Returns non-zero on the first violation so it plugs into CI.

set -euo pipefail

# Fixed-string presence helper reading from a here-string. We
# deliberately avoid `printf ... | grep -q` because `grep -q` exits on
# the first match, closing the pipe; with `pipefail` set, the upstream
# `printf` then dies with SIGPIPE (141) and the pipeline reports failure
# INTERMITTENTLY even though the pattern WAS found. Here-strings have no
# upstream process and are immune (same helper as check_rdp_cert_paths.sh).
has() { grep -qF -- "$1" <<<"$2"; }

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

errors=0

SSH_HANDLER="${ROOT}/src/handlers/web/ssh.rs"
SHARED_MSG="${ROOT}/../shared/src/messages.rs"
PROXY_SSH_IPC="${ROOT}/src/ipc/proxy_ssh.rs"

if [[ ! -f "${SSH_HANDLER}" ]]; then
    echo "[lint] missing file: ${SSH_HANDLER}" >&2
    exit 1
fi

# ---- 1. amber "Could not verify" fragment is wired in ----
#
# We require AT LEAST two includes of the unverified fragment in
# `ssh.rs`: one for the proxy-unavailable branch, one for the
# fetch_host_key Err branch. Strip Rust line comments first so
# documentation that mentions the file name does not count.
stripped_ssh="$(sed 's|//.*$||' "${SSH_HANDLER}")"
unverified_count="$(printf '%s' "${stripped_ssh}" \
    | grep -cE '_ssh_host_key_unverified_fragment\.html' || true)"
if [[ "${unverified_count}" -lt 2 ]]; then
    echo "[lint] forbidden: \`_ssh_host_key_unverified_fragment.html\` appears ${unverified_count} time(s) in ${SSH_HANDLER}"
    echo "       Issue #34 wires this amber fragment in TWO branches of"
    echo "       verify_ssh_host_key (proxy unavailable AND fetch Err)."
    echo "       Removing one re-opens the silent green regression."
    errors=1
fi

# ---- 2. Strict-pin refusal messages in connect_ssh ----
if ! has 'No SSH host key pinned' "${stripped_ssh}"; then
    echo "[lint] forbidden: missing literal \"No SSH host key pinned\" in ${SSH_HANDLER}"
    echo "       Issue #34 connect_ssh pre-flight refuses categorically when"
    echo "       no host key is pinned. The literal is the user-visible"
    echo "       message; removing it re-opens the indefinite TOFU window."
    errors=1
fi
if ! has 'SSH host key mismatch detected on previous connection' "${stripped_ssh}"; then
    echo "[lint] forbidden: missing literal \"SSH host key mismatch detected on previous connection\" in ${SSH_HANDLER}"
    echo "       Issue #34 connect_ssh pre-flight refuses when the mismatch"
    echo "       flag is set. Removing this literal would let users retry"
    echo "       connecting to a suspected MITM target."
    errors=1
fi

# ---- 3. verify_ssh_host_key threads `assets:manage` through ----
#
# We assert two things, both inside ssh.rs: the verify handler must
# read `perms.assets_manage` and forward it to `HostKeyFetchIdentity`
# via the new `caller_has_assets_manage` field. Without these, the
# IPC layer falls back to the legacy session-token verb and the
# admin path silently denies again.
if ! has 'perms.assets_manage' "${stripped_ssh}"; then
    echo "[lint] forbidden: ${SSH_HANDLER} no longer reads \`perms.assets_manage\`"
    echo "       Issue #34 verify_ssh_host_key (and fetch_ssh_host_key) MUST"
    echo "       forward this Casbin flag so the IPC layer routes admin"
    echo "       callers to the diagnostic-token verb."
    errors=1
fi
if ! has 'caller_has_assets_manage' "${stripped_ssh}"; then
    echo "[lint] forbidden: ${SSH_HANDLER} no longer constructs \`HostKeyFetchIdentity\` with \`caller_has_assets_manage\`"
    echo "       Issue #34: this field gates the diagnostic-token bypass."
    errors=1
fi

# ---- 4. shared IPC enum carries the diagnostic-token variant ----
if [[ ! -f "${SHARED_MSG}" ]]; then
    echo "[lint] missing file: ${SHARED_MSG}" >&2
    errors=1
elif ! grep -qF 'IssueDiagnosticToken' "${SHARED_MSG}"; then
    echo "[lint] forbidden: ${SHARED_MSG} no longer defines \`AccessRequest::IssueDiagnosticToken\`"
    echo "       Issue #34 Lot 2: removing it breaks bincode wire-format"
    echo "       compatibility AND re-opens the host-key regression."
    errors=1
fi

# ---- 5. proxy_ssh IPC routes admin callers to issue_diagnostic_token ----
if [[ ! -f "${PROXY_SSH_IPC}" ]]; then
    echo "[lint] missing file: ${PROXY_SSH_IPC}" >&2
    errors=1
else
    stripped_ipc="$(sed 's|//.*$||' "${PROXY_SSH_IPC}")"
    if ! has 'issue_diagnostic_token' "${stripped_ipc}"; then
        echo "[lint] forbidden: ${PROXY_SSH_IPC} no longer calls \`issue_diagnostic_token\`"
        echo "       Issue #34 Lot 2: \`fetch_host_key\` must route admin"
        echo "       callers through the diagnostic-token verb."
        errors=1
    fi
    if ! has 'pub caller_has_assets_manage' "${stripped_ipc}"; then
        echo "[lint] forbidden: ${PROXY_SSH_IPC} no longer exposes"
        echo "       \`pub caller_has_assets_manage\` on HostKeyFetchIdentity."
        echo "       Issue #34: removing this field forces every caller back"
        echo "       to the legacy session-token verb."
        errors=1
    fi
fi

if [[ ${errors} -ne 0 ]]; then
    echo >&2
    echo "[lint] One or more issue #34 SSH host-key invariants violated." >&2
    echo "[lint] See vauban-web/tests/web/ssh_host_key_no_silent_green_test.rs" >&2
    echo "[lint] and vauban-web/tests/web/ssh_host_key_e2e_test.rs for the" >&2
    echo "[lint] full coverage matrix." >&2
    exit 1
fi

echo "[lint] issue #34: SSH host-key paths intact (amber fallback wired,"
echo "[lint]            connect_ssh pre-flight in place, diagnostic-token"
echo "[lint]            routing for assets:manage callers preserved)"
