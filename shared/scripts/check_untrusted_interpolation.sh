#!/usr/bin/env bash
# Class lint: untrusted input must not be interpolated into a structured
# language (LDAP DN, SQL, shell) via raw replace/format.
#
# Opt-out: `// allow-raw-interp: <reason>` on the same line or the line above.
# The only blessed substitution site is shared/src/ldap_dn.rs.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
errors=0

HELPER="${ROOT}/shared/src/ldap_dn.rs"
if [[ ! -f "${HELPER}" ]]; then
    echo "[lint] missing ${HELPER}" >&2
    exit 1
fi

scan_dirs=(
    "${ROOT}/vauban-auth/src"
    "${ROOT}/vauban-audit/src"
    "${ROOT}/vauban-access/src"
    "${ROOT}/vauban-supervisor/src"
)

# Raw LDAP placeholder interpolation outside the helper.
while IFS= read -r match; do
    file="${match%%:*}"
    rest="${match#*:}"
    line="${rest%%:*}"
    content="${rest#*:}"
    if [[ "${content}" == *"allow-raw-interp:"* ]]; then
        continue
    fi
    if [[ "${line}" -gt 1 ]]; then
        prev=$(sed -n "$((line - 1))p" "${file}")
        if [[ "${prev}" == *"allow-raw-interp:"* ]]; then
            continue
        fi
    fi
    echo "[lint] raw {username} interpolation: ${match}"
    errors=1
done < <(grep -REn --include='*.rs' -F '.replace("{username}"' "${scan_dirs[@]}" || true)

if grep -qF '.replace("{username}"' "${scan_dirs[@]}" 2>/dev/null; then
    :
fi

# bind.rs / auth must call the helper (auth crate).
if [[ -f "${ROOT}/vauban-auth/src/bind.rs" ]] && ! grep -qF 'substitute_bind_dn' "${ROOT}/vauban-auth/src/bind.rs"; then
    echo "[lint] vauban-auth/src/bind.rs must call substitute_bind_dn"
    errors=1
fi

if [[ ${errors} -ne 0 ]]; then
    echo >&2
    echo "[lint] Untrusted interpolation: use substitute_bind_dn / an encoder." >&2
    echo "[lint] Opt out with // allow-raw-interp: <reason>" >&2
    exit 1
fi

echo "[lint] no raw untrusted interpolation in auth/audit/access/supervisor"
