#!/usr/bin/env bash
# Structural lint: LDAP bind DNs MUST be built by shared::ldap_dn::substitute_bind_dn.
# A raw `dn_template.replace("{username}", ...)` is LDAP DN injection.
#
# Returns non-zero on the first violation so it plugs into `just lint` / cargo test.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
AUTH_SRC="${ROOT}/vauban-auth/src"
HELPER="${ROOT}/shared/src/ldap_dn.rs"

errors=0

if [[ ! -f "${HELPER}" ]]; then
    echo "[lint] missing ${HELPER}" >&2
    echo "       bind-DN construction must live in shared::ldap_dn." >&2
    exit 1
fi

stripped_helper="$(sed 's|//.*$||' "${HELPER}")"
for token in 'fn substitute_bind_dn' 'fn username_allowed_in_bind_dn' 'IllegalUsername'; do
    if ! grep -qF -- "${token}" <<<"${stripped_helper}"; then
        echo "[lint] ${HELPER} no longer defines \`${token}\`"
        errors=1
    fi
done

# The helper is the ONLY place allowed to interpolate {username}.
if ! grep -qF '.replace("{username}"' "${HELPER}"; then
    echo "[lint] ${HELPER} must be the single substitution site (replace(\"{username}\"))"
    errors=1
fi

while IFS= read -r match; do
    echo "[lint] forbidden raw username interpolation: ${match}"
    errors=1
done < <(grep -REn --include='*.rs' -F '.replace("{username}"' "${AUTH_SRC}" || true)

if ! grep -qF 'substitute_bind_dn' "${AUTH_SRC}/bind.rs"; then
    echo "[lint] vauban-auth/src/bind.rs must call substitute_bind_dn"
    errors=1
fi

if [[ ${errors} -ne 0 ]]; then
    echo >&2
    echo "[lint] LDAP bind DN must go through shared::ldap_dn::substitute_bind_dn." >&2
    exit 1
fi

echo "[lint] LDAP bind DN substitution is fail-closed (allowlist + single helper)"
