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

echo "[lint] WORM / signature verify uses an out-of-band pin"
