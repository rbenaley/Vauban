#!/usr/bin/env bash
# Structural lint: the [patch.crates-io] entries of the workspace manifest.
#
# 1. Every entry is pinned by a full commit id. Cargo.lock is not
#    versioned: an entry without `rev` builds whatever its branch holds
#    that day.
# 2. ironrdp-connector is taken from the fork that sets the ASN.1 slot of
#    the redirected Kerberos responses. Without it a Remote Credential
#    Guard session has no outbound identity, and the published crate has
#    no Remote Credential Guard at all.
# 3. Every ironrdp-* entry points at that fork and at one single rev. Two
#    revs, or one crate left on another source, are two copies of the same
#    types.
# 4. There is no sspi entry. sspi 0.23.1 from crates.io holds the Windows
#    mechListMIC fix; an entry would put an older sspi back under it.
#
# Uses grep (not rg) so cargo-test sandboxes without ripgrep still pass.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MANIFEST="${1:-$(cd "${ROOT}/.." && pwd)/Cargo.toml}"
IRONRDP_FORK='https://github.com/rbenaley/IronRDP-vb'
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

ironrdp_entries="$(printf '%s\n' "${entries}" | grep -E '^ironrdp-[a-z0-9-]+[[:space:]]*=' || true)"
if ! printf '%s\n' "${ironrdp_entries}" | grep -Eq '^ironrdp-connector[[:space:]]*='; then
    fail "the ironrdp-connector entry is gone from [patch.crates-io]: the published crate has no Remote Credential Guard and does not set KERB_ASN1_DATA.Pdu. If a published IronRDP release now does both, remove the ironrdp rules with the entries."
fi
while IFS= read -r entry; do
    [ -z "${entry}" ] && continue
    if ! printf '%s\n' "${entry}" | grep -Fq "git = \"${IRONRDP_FORK}\""; then
        fail "an ironrdp entry must point at ${IRONRDP_FORK}: ${entry}"
    fi
done <<< "${ironrdp_entries}"
ironrdp_revs="$(printf '%s\n' "${ironrdp_entries}" | grep -Eo 'rev = "[0-9a-f]{40}"' | sort -u | wc -l | tr -d ' ')"
if [ "${ironrdp_revs}" -gt 1 ]; then
    fail "the ironrdp entries of [patch.crates-io] are on ${ironrdp_revs} different revs: they must share one"
fi

if printf '%s\n' "${entries}" | grep -Eq '^sspi[[:space:]]*='; then
    fail "an sspi entry is back in [patch.crates-io]: sspi 0.23.1 from crates.io holds the Windows mechListMIC fix and Remote Credential Guard needs it"
fi

if [ "${errors}" -ne 0 ]; then
    exit 1
fi
echo "patch pins ok"
