#!/usr/bin/env bash
# VAU-001 -- structural lint: pin the RDP server-certificate end-to-end
# paths. Strict mirror of `check_ssh_host_key_paths.sh`, plus the
# proxy-rdp pinning invariants.
#
# Regressions guarded against forever:
#
# 1. `verify_rdp_server_cert` returning the GREEN "RDP Server Certificate
#    Verified" fragment from a fallback / Err / proxy-unavailable branch
#    (silent green). The fix introduces an AMBER "Could not verify"
#    fragment for those branches.
#
# 2. `connect_rdp` opening a session when no certificate is pinned or when
#    the mismatch flag is set. The fix is a strict pre-flight gate that
#    refuses with one of two user-visible messages.
#
# 3. The proxy reverting to the pre-fix `NoCertificateVerification`
#    (accept-any) verifier on the SESSION path (trivial MITM). The session
#    config MUST install `PinningServerCertVerifier`; the accept-any
#    verifier is confined to the dedicated fetch path.
#
# Companion of:
#   - vauban-web/tests/web/rdp_cert_no_silent_green_test.rs
#   - vauban-web/tests/web/rdp_cert_pin_e2e_test.rs
#   - vauban-proxy-rdp/src/session.rs (rdp_cert_behavioural_tests)
#
# Returns non-zero on the first violation so it plugs into CI.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

errors=0

RDP_HANDLER="${ROOT}/src/handlers/web/rdp.rs"
SHARED_MSG="${ROOT}/../shared/src/messages.rs"
PROXY_RDP_IPC="${ROOT}/src/ipc/proxy_rdp.rs"
PROXY_RDP_SESSION="${ROOT}/../vauban-proxy-rdp/src/session.rs"

# Fixed-string / regex presence helpers that read from a here-string. We
# deliberately avoid `printf ... | grep -q` because `grep -q` exits on the
# first match, closing the pipe; with `pipefail` set, the upstream `printf`
# then dies with SIGPIPE and the whole pipeline reports failure even though
# the pattern WAS found. Here-strings have no upstream process and so are
# immune to that false negative.
has() { grep -qF -- "$1" <<<"$2"; }
hasE() { grep -qE -- "$1" <<<"$2"; }

if [[ ! -f "${RDP_HANDLER}" ]]; then
    echo "[lint] missing file: ${RDP_HANDLER}" >&2
    exit 1
fi

# Strip Rust line comments so docs mentioning a fragment / literal do not
# count as a wiring.
stripped_rdp="$(sed 's|//.*$||' "${RDP_HANDLER}")"

# ---- 1. amber "Could not verify" fragment is wired in (>= 2 branches) ----
unverified_count="$(grep -cE '_rdp_server_cert_unverified_fragment\.html' <<<"${stripped_rdp}" || true)"
if [[ "${unverified_count}" -lt 2 ]]; then
    echo "[lint] forbidden: \`_rdp_server_cert_unverified_fragment.html\` appears ${unverified_count} time(s) in ${RDP_HANDLER}"
    echo "       VAU-001 wires this amber fragment in TWO branches of"
    echo "       verify_rdp_server_cert (proxy unavailable AND fetch Err)."
    echo "       Removing one re-opens the silent green regression."
    errors=1
fi

# ---- 2. Strict-pin refusal messages in connect_rdp ----
if ! has 'No RDP server certificate pinned for this asset' "${stripped_rdp}"; then
    echo "[lint] forbidden: missing literal \"No RDP server certificate pinned for this asset\" in ${RDP_HANDLER}"
    echo "       VAU-001 connect_rdp pre-flight refuses categorically when no"
    echo "       certificate is pinned. Removing it re-opens the MITM hole."
    errors=1
fi
if ! has 'RDP server certificate mismatch detected on previous connection' "${stripped_rdp}"; then
    echo "[lint] forbidden: missing literal \"RDP server certificate mismatch detected on previous connection\" in ${RDP_HANDLER}"
    echo "       VAU-001 connect_rdp pre-flight refuses when the mismatch flag"
    echo "       is set. Removing this literal would let users retry connecting"
    echo "       to a suspected MITM target."
    errors=1
fi

# ---- 3. verify/fetch handlers thread `assets:manage` through ----
if ! has 'perms.assets_manage' "${stripped_rdp}"; then
    echo "[lint] forbidden: ${RDP_HANDLER} no longer reads \`perms.assets_manage\`"
    echo "       VAU-001 verify_rdp_server_cert + fetch_rdp_server_cert MUST"
    echo "       forward this Casbin flag so the IPC layer routes admin callers"
    echo "       to the diagnostic-token verb."
    errors=1
fi
if ! has 'caller_has_assets_manage' "${stripped_rdp}"; then
    echo "[lint] forbidden: ${RDP_HANDLER} no longer constructs \`CertFetchIdentity\` with \`caller_has_assets_manage\`"
    errors=1
fi

# ---- 4. shared IPC enum carries the RDP cert variants + pin field ----
if [[ ! -f "${SHARED_MSG}" ]]; then
    echo "[lint] missing file: ${SHARED_MSG}" >&2
    errors=1
else
    shared_msg_contents="$(cat "${SHARED_MSG}")"
    for variant in RdpFetchServerCert RdpServerCertResult expected_cert_fingerprint; do
        if ! has "${variant}" "${shared_msg_contents}"; then
            echo "[lint] forbidden: ${SHARED_MSG} no longer defines \`${variant}\`"
            echo "       VAU-001: removing it breaks the cert-pinning wire format."
            errors=1
        fi
    done
fi

# ---- 5. proxy_rdp IPC routes admin callers to issue_diagnostic_token ----
if [[ ! -f "${PROXY_RDP_IPC}" ]]; then
    echo "[lint] missing file: ${PROXY_RDP_IPC}" >&2
    errors=1
else
    stripped_ipc="$(sed 's|//.*$||' "${PROXY_RDP_IPC}")"
    if ! has 'issue_diagnostic_token' "${stripped_ipc}"; then
        echo "[lint] forbidden: ${PROXY_RDP_IPC} no longer calls \`issue_diagnostic_token\`"
        echo "       VAU-001: fetch_server_cert must route admin callers through"
        echo "       the diagnostic-token verb."
        errors=1
    fi
    if ! has 'pub caller_has_assets_manage' "${stripped_ipc}"; then
        echo "[lint] forbidden: ${PROXY_RDP_IPC} no longer exposes \`pub caller_has_assets_manage\` on CertFetchIdentity."
        errors=1
    fi
fi

# ---- 6. proxy-rdp session path pins, never accept-any ----
if [[ ! -f "${PROXY_RDP_SESSION}" ]]; then
    echo "[lint] missing file: ${PROXY_RDP_SESSION}" >&2
    errors=1
else
    stripped_session="$(sed 's|//.*$||' "${PROXY_RDP_SESSION}")"
    # The pre-fix accept-any session verifier MUST be gone.
    if hasE 'struct[[:space:]]+NoCertificateVerification' "${stripped_session}"; then
        echo "[lint] forbidden: ${PROXY_RDP_SESSION} still defines \`NoCertificateVerification\`"
        echo "       VAU-001: the accept-any session verifier is the MITM hole."
        errors=1
    fi
    # The session config MUST install the pinning verifier.
    if ! has 'PinningServerCertVerifier' "${stripped_session}"; then
        echo "[lint] forbidden: ${PROXY_RDP_SESSION} no longer installs \`PinningServerCertVerifier\`"
        echo "       VAU-001: the session TLS path MUST pin the server SPKI."
        errors=1
    fi
    # build_tls_config (session path) MUST take the expected fingerprint.
    if ! hasE 'fn[[:space:]]+build_tls_config[[:space:]]*\([[:space:]]*expected_fingerprint' "${stripped_session}"; then
        echo "[lint] forbidden: ${PROXY_RDP_SESSION} build_tls_config no longer"
        echo "       takes \`expected_fingerprint\`; the pin would not be enforced."
        errors=1
    fi
    # The accept-any verifier, if present, MUST be the dedicated fetch one.
    if has 'ServerCertVerified::assertion()' "${stripped_session}" \
        && ! has 'TofuAcceptAnyFetchVerifier' "${stripped_session}"; then
        echo "[lint] forbidden: ${PROXY_RDP_SESSION} returns \`ServerCertVerified::assertion()\`"
        echo "       without the confined \`TofuAcceptAnyFetchVerifier\` (fetch path)."
        errors=1
    fi
fi

if [[ ${errors} -ne 0 ]]; then
    echo >&2
    echo "[lint] One or more VAU-001 RDP server-certificate invariants violated." >&2
    echo "[lint] See vauban-web/tests/web/rdp_cert_no_silent_green_test.rs and" >&2
    echo "[lint] vauban-web/tests/web/rdp_cert_pin_e2e_test.rs for the full" >&2
    echo "[lint] coverage matrix." >&2
    exit 1
fi

echo "[lint] VAU-001: RDP server-certificate paths intact (amber fallback"
echo "[lint]          wired, connect_rdp pre-flight in place, session path"
echo "[lint]          pins SPKI, diagnostic-token routing preserved)"
