#!/usr/bin/env bash
#
# Lint: the routes that pin a trust anchor on an asset check the CSRF
# token, and take the "replace a changed pin" confirmation from the body.
#
# `fetch_ssh_host_key` stores the SSH host key of an asset and
# `fetch_rdp_server_cert` its RDP server certificate. Both decide what the
# bastion accepts as the identity of a target. Without the token, a page
# the administrator visits could pin a key on their behalf; with
# `?confirm=true` in the URL, a link was enough to replace a pin.
#
# Mirrors `tests/web/pin_csrf_test.rs` so the regression is caught before
# `cargo test`.
#
# Usage: bash vauban-web/scripts/check_pin_routes_csrf.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
HANDLERS="${CRATE_DIR}/src/handlers/web"
TEMPLATES="${CRATE_DIR}/templates"

status=0

# 1. Each pin handler validates the token and reads `confirm` from the form.
for pair in "ssh.rs:fetch_ssh_host_key" "rdp.rs:fetch_rdp_server_cert"; do
    file="${HANDLERS}/${pair%%:*}"
    name="${pair##*:}"
    # The handler: from its signature to the next top-level `pub async fn`.
    body="$(awk -v n="pub async fn ${name}(" '
        index($0, n) { on = 1 }
        on && /^pub async fn / && !index($0, n) { exit }
        on { print }
    ' "${file}")"
    if [[ -z "${body}" ]]; then
        echo "FAIL: handler ${name} not found in ${file}" >&2
        status=1
        continue
    fi
    if ! grep -q 'pin_request_csrf_is_valid(&state, &jar, &form)' <<<"${body}"; then
        echo "FAIL: ${name} does not validate the CSRF token." >&2
        status=1
    fi
    if ! grep -q 'form.confirmed()' <<<"${body}"; then
        echo "FAIL: ${name} does not read confirm from the validated form." >&2
        status=1
    fi
    if grep -q 'Query(' <<<"${body}"; then
        echo "FAIL: ${name} takes query parameters; confirm must come from the body." >&2
        status=1
    fi
done

# 2. No template puts the confirmation in the URL of a pin action.
if grep -RnE 'fetch-(host-key|rdp-cert)\?confirm' "${TEMPLATES}" >&2; then
    echo "FAIL: a template sends confirm in the URL of a pin action." >&2
    status=1
fi

if [[ "${status}" -eq 0 ]]; then
    echo "OK: pin routes check the CSRF token and take confirm from the body."
fi
exit "${status}"
