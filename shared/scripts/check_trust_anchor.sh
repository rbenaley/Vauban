#!/usr/bin/env bash
# Class lint: a VerifyingKey used to check a seal/signature must not be
# built solely from the object under verification.
#
# Opt-out: `// allow-inband-key: <reason>` on the same line or the line above.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORM="${ROOT}/vauban-audit/src/worm.rs"
errors=0

if [[ ! -f "${WORM}" ]]; then
    echo "[lint] missing ${WORM}" >&2
    exit 1
fi

stripped="$(sed 's|//.*$||' "${WORM}")"
for token in 'expected: &VerifyingKey' 'PubkeyMismatch' 'expected.to_bytes()'; do
    if ! grep -qF -- "${token}" <<<"${stripped}"; then
        echo "[lint] ${WORM} must pin seals with \`${token}\`"
        errors=1
    fi
done

while IFS= read -r match; do
    file="${match%%:*}"
    rest="${match#*:}"
    line="${rest%%:*}"
    content="${rest#*:}"
    if [[ "${content}" == *"allow-inband-key:"* ]]; then
        continue
    fi
    if [[ "${line}" -gt 1 ]]; then
        prev=$(sed -n "$((line - 1))p" "${file}")
        if [[ "${prev}" == *"allow-inband-key:"* ]]; then
            continue
        fi
    fi
    echo "[lint] in-band VerifyingKey from seal pubkey: ${match}"
    errors=1
done < <(grep -REn --include='*.rs' -E 'VerifyingKey::from_bytes\(&pubkey_bytes\)' \
    "${ROOT}/vauban-audit/src" "${ROOT}/vauban-auth/src" "${ROOT}/vauban-access/src" \
    "${ROOT}/vauban-supervisor/src" || true)

if [[ ${errors} -ne 0 ]]; then
    echo >&2
    echo "[lint] Trust anchors must be out of band. Opt out: // allow-inband-key:" >&2
    exit 1
fi

for f in "${ROOT}/shared/src/tls_pin.rs" "${ROOT}/vauban-mcp/src/inner.rs" "${ROOT}/vauban-proxy-mcp/src/tls_pin.rs"; do
    if [[ ! -f "${f}" ]]; then
        echo "[lint] missing ${f}" >&2
        errors=1
        continue
    fi
    if grep -q 'danger_accept_invalid_certs' "${f}"; then
        echo "[lint] ${f} must not disable certificate checks" >&2
        errors=1
    fi
done
if ! grep -q 'pins_match' "${ROOT}/shared/src/tls_pin.rs"; then
    echo "[lint] shared tls pin must compare to an expected pin" >&2
    errors=1
fi

# vauban-mcp TOFU: the pin is filed under the --url origin, never under
# a URL the bastion returned, and plain http/ws is never an accepted scheme.
SHIM="${ROOT}/vauban-mcp/src"
shim_prod() { sed '/#\[cfg(test)\]/,$d' "$1" | sed 's|//.*$||'; }
if ! shim_prod "${SHIM}/session.rs" | grep -qF 'accept_pin(cli_origin,'; then
    echo "[lint] vauban-mcp post_tunnel must key the TOFU pin on the CLI origin" >&2
    errors=1
fi
if ! shim_prod "${SHIM}/hop.rs" | grep -qF 'origin != expected_origin'; then
    echo "[lint] vauban-mcp parse_hop1 must refuse a hop-1 url off the --url origin" >&2
    errors=1
fi
for f in "${SHIM}"/*.rs; do
    if shim_prod "${f}" | grep -qE 'starts_with\("(http|ws)://"\)|strip_prefix\("(http|ws)://"\)'; then
        echo "[lint] ${f} accepts a plain http:// or ws:// scheme" >&2
        errors=1
    fi
    # The TOFU store map is read and written by tofu.rs only (observe and
    # the legacy migration); every other file goes through accept_pin.
    if [[ "$(basename "${f}")" != "tofu.rs" ]] \
        && shim_prod "${f}" | grep -qE '\bstore\.(get|insert|remove|entry)\('; then
        echo "[lint] ${f} reads or writes the TOFU store outside tofu.rs" >&2
        errors=1
    fi
done
# A TOFU key never comes from a URL hop 1 returned.
if shim_prod "${SHIM}/session.rs" | grep -qE '(accept_pin|observe)\([^;]*hop\.'; then
    echo "[lint] vauban-mcp session.rs keys the TOFU pin on a hop-1 field" >&2
    errors=1
fi
if ! shim_prod "${SHIM}/session.rs" | grep -qF 'tofu::observe(&mut store, origin, advertised)'; then
    echo "[lint] vauban-mcp accept_pin must observe the pin under the origin it was given" >&2
    errors=1
fi
if [[ ${errors} -ne 0 ]]; then
    exit 1
fi

echo "[lint] WORM / signature verify uses an out-of-band pin"
