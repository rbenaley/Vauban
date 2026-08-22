#!/usr/bin/env bash
# Class lint: untrusted input must not be interpolated into a structured
# language (LDAP DN, SQL, shell) via raw replace/format.
#
# Opt-out: `// allow-raw-interp: <reason>` on the same line or the line above.
# Blessed sites: shared/src/ldap_dn.rs (`{username}` bind) and
# shared/src/ldap_mapping.rs (`{name}` is a capture, never format!/replace).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
errors=0

HELPER="${ROOT}/shared/src/ldap_dn.rs"
if [[ ! -f "${HELPER}" ]]; then
    echo "[lint] missing ${HELPER}" >&2
    exit 1
fi

scan_dirs=(
    "${ROOT}/shared/src"
    "${ROOT}/vauban-auth/src"
    "${ROOT}/vauban-audit/src"
    "${ROOT}/vauban-access/src"
    "${ROOT}/vauban-supervisor/src"
    "${ROOT}/vauban-web/src"
)

opted_out() {
    local file="$1"
    local line="$2"
    local content="$3"
    if [[ "${content}" == *"allow-raw-interp:"* ]]; then
        return 0
    fi
    if [[ "${line}" -gt 1 ]]; then
        local prev
        prev=$(sed -n "$((line - 1))p" "${file}")
        if [[ "${prev}" == *"allow-raw-interp:"* ]]; then
            return 0
        fi
    fi
    return 1
}

# Raw LDAP placeholder interpolation outside the helper.
while IFS= read -r match; do
    [[ -z "${match}" ]] && continue
    file="${match%%:*}"
    rest="${match#*:}"
    line="${rest%%:*}"
    content="${rest#*:}"
    if opted_out "${file}" "${line}" "${content}"; then
        continue
    fi
    # The bind helper is the only site allowed to replace {username}.
    if [[ "${file}" == "${HELPER}" ]]; then
        continue
    fi
    echo "[lint] raw {username} interpolation: ${match}"
    errors=1
done < <(grep -REn --include='*.rs' -F '.replace("{username}"' "${scan_dirs[@]}" || true)

# {name} is a mapping capture. `.replace("{name}"` anywhere is R1.
# `format!(...{name}...)` is only meaningful in LDAP modules (other crates
# use a local `name` variable in format! for hostnames / labels).
while IFS= read -r match; do
    [[ -z "${match}" ]] && continue
    file="${match%%:*}"
    rest="${match#*:}"
    line="${rest%%:*}"
    content="${rest#*:}"
    if opted_out "${file}" "${line}" "${content}"; then
        continue
    fi
    echo "[lint] raw {name} interpolation: ${match}"
    errors=1
done < <(
    grep -REn --include='*.rs' -F '.replace("{name}"' "${scan_dirs[@]}" || true
    grep -REn --include='ldap*.rs' -E 'format!\([^;]*\{name\}' "${scan_dirs[@]}" || true
)

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

echo "[lint] no raw untrusted interpolation in shared/auth/audit/access/supervisor/web"
