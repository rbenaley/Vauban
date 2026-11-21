#!/usr/bin/env bash
# Structural lint: the [patch.crates-io] entries of the workspace manifest.
#
# 1. Every entry is pinned by a full commit id. Cargo.lock is not
#    versioned: an entry without `rev` builds whatever its branch holds
#    that day.
# 2. ironrdp-connector is taken from upstream IronRDP by commit: the
#    published crate has no Remote Credential Guard.
# 3. Every ironrdp-* entry points at that repository and at one single
#    rev. Two revs, or one crate left on another source, are two copies
#    of the same types.
# 4. There is no sspi entry. sspi 0.23.1 from crates.io holds the Windows
#    mechListMIC fix; an entry would put an older sspi back under it.
# 5. A crate the proxy takes from that repository directly (ironrdp-rdpear
#    is not on crates.io, so it cannot be a patch entry) is pinned by the
#    same rev as the patch entries. Another rev would be a second copy,
#    with its own types.
# 6. The proxy does not enable the connector's `remote-guard` feature: it
#    brings sspi's DNS resolver, and a channel backend that returns
#    KERB_ASN1_DATA.Pdu as 0. The proxy has its own backend.
#
# Uses grep (not rg) so cargo-test sandboxes without ripgrep still pass.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MANIFEST="${1:-$(cd "${ROOT}/.." && pwd)/Cargo.toml}"
PROXY_MANIFEST="${2:-${ROOT}/Cargo.toml}"
IRONRDP_REPO='https://github.com/Devolutions/IronRDP'
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
    fail "the ironrdp-connector entry is gone from [patch.crates-io]: the published crate has no Remote Credential Guard. If a published IronRDP release now has it, remove the ironrdp rules with the entries."
fi
while IFS= read -r entry; do
    [ -z "${entry}" ] && continue
    if ! printf '%s\n' "${entry}" | grep -Fq "git = \"${IRONRDP_REPO}\""; then
        fail "an ironrdp entry must point at ${IRONRDP_REPO}: ${entry}"
    fi
done <<< "${ironrdp_entries}"
ironrdp_revs="$(printf '%s\n' "${ironrdp_entries}" | grep -Eo 'rev = "[0-9a-f]{40}"' | sort -u | wc -l | tr -d ' ')"
if [ "${ironrdp_revs}" -gt 1 ]; then
    fail "the ironrdp entries of [patch.crates-io] are on ${ironrdp_revs} different revs: they must share one"
fi

patch_rev="$(printf '%s\n' "${ironrdp_entries}" | grep -Eo 'rev = "[0-9a-f]{40}"' | sort -u | head -n 1)"
direct="$(grep -E '^ironrdp-[a-z0-9-]+[[:space:]]*=.*git = ' "${PROXY_MANIFEST}" || true)"
while IFS= read -r entry; do
    [ -z "${entry}" ] && continue
    if ! printf '%s\n' "${entry}" | grep -Fq "git = \"${IRONRDP_REPO}\""; then
        fail "a git dependency on IronRDP must point at ${IRONRDP_REPO}: ${entry}"
    fi
    if printf '%s\n' "${entry}" | grep -Eq '(branch|tag) = '; then
        fail "a git dependency on IronRDP is pinned by branch or tag, not by rev: ${entry}"
    fi
    if [ -z "${patch_rev}" ] || ! printf '%s\n' "${entry}" | grep -Fq "${patch_rev}"; then
        fail "a git dependency on IronRDP in ${PROXY_MANIFEST} is not on the rev of [patch.crates-io]: ${entry}"
    fi
done <<< "${direct}"

if grep -E '^ironrdp-connector[[:space:]]*=' "${PROXY_MANIFEST}" | grep -q 'remote-guard'; then
    fail "the proxy enables the connector's remote-guard feature: it brings sspi's DNS resolver and a channel backend that returns KERB_ASN1_DATA.Pdu as 0. The proxy's backend is src/remote_guard_channel.rs"
fi

if printf '%s\n' "${entries}" | grep -Eq '^sspi[[:space:]]*='; then
    fail "an sspi entry is back in [patch.crates-io]: sspi 0.23.1 from crates.io holds the Windows mechListMIC fix and Remote Credential Guard needs it"
fi

if [ "${errors}" -ne 0 ]; then
    exit 1
fi
echo "patch pins ok"
