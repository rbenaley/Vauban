#!/usr/bin/env bash
# Structural lint: the [patch.crates-io] entries of the workspace manifest.
#
# 1. Every entry is pinned by a full commit id. Cargo.lock is not
#    versioned: an entry without `rev` builds whatever its branch holds
#    that day.
# 2. The sspi entry is present and points at the fork carrying the
#    Windows mechListMIC fix. Without it both Kerberos RDP modes fail
#    against every Windows target (sspi 0.23.0, upstream issue #772).
#
# Uses grep (not rg) so cargo-test sandboxes without ripgrep still pass.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MANIFEST="${1:-$(cd "${ROOT}/.." && pwd)/Cargo.toml}"
errors=0

fail() {
    echo "[lint] $*" >&2
    errors=1
}

# The entries of the section: from its header to the next header, without
# comments and blank lines.
entries="$(awk '
    /^\[patch\.crates-io\]/ { inside = 1; next }
    /^\[/ { inside = 0 }
    inside && !/^[[:space:]]*(#|$)/ { print }
' "${MANIFEST}")"

if [ -z "${entries}" ]; then
    fail "no [patch.crates-io] entry found in ${MANIFEST}"
fi

while IFS= read -r entry; do
    [ -z "${entry}" ] && continue
    if ! printf '%s\n' "${entry}" | grep -Eq 'rev = "[0-9a-f]{40}"'; then
        fail "[patch.crates-io] entry without a 40-character rev: ${entry}"
    fi
    if printf '%s\n' "${entry}" | grep -Eq '(branch|tag) = '; then
        fail "[patch.crates-io] entry pinned by branch or tag, not by rev: ${entry}"
    fi
done <<< "${entries}"

sspi_entry="$(printf '%s\n' "${entries}" | grep -E '^sspi[[:space:]]*=' || true)"
if [ -z "${sspi_entry}" ]; then
    fail "the sspi entry is gone from [patch.crates-io]: sspi 0.23.0 refuses the Windows mechListMIC. If IronRDP now resolves sspi >= 0.23.1 (cargo tree -p sspi), remove this rule with it."
elif ! printf '%s\n' "${sspi_entry}" | grep -Fq 'https://github.com/rbenaley/sspi-rs-vb'; then
    fail "the sspi entry must point at https://github.com/rbenaley/sspi-rs-vb: ${sspi_entry}"
fi

if [ "${errors}" -ne 0 ]; then
    exit 1
fi
echo "patch pins ok"
