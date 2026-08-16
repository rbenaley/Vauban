#!/usr/bin/env bash
# A rustdoc claim "attacker who" / "cannot forge" in production src must
# be backed by an attack test in the same crate
# (`attack_*` / `forged_*` / `*_is_rejected`).
#
# Opt-out: `// allow-untested-claim: <reason>` on the same line or above.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
errors=0

crates=(vauban-auth vauban-audit vauban-access vauban-supervisor vauban-web vauban-vault shared)

has_attack_test() {
    local crate_dir="$1"
    grep -REl --include='*.rs' -E 'fn (attack_|forged_)|fn \w+_is_rejected' \
        "${crate_dir}/src" "${crate_dir}/tests" 2>/dev/null | grep -q .
}

while IFS= read -r match; do
    [[ -z "${match}" ]] && continue
    file="${match%%:*}"
    rest="${match#*:}"
    line="${rest%%:*}"
    content="${rest#*:}"
    if [[ "${content}" == *"allow-untested-claim:"* ]]; then
        continue
    fi
    if [[ "${line}" -gt 1 ]]; then
        prev=$(sed -n "$((line - 1))p" "${file}")
        if [[ "${prev}" == *"allow-untested-claim:"* ]]; then
            continue
        fi
    fi
    crate_dir="${file}"
    # Walk up to the crate root (directory that contains Cargo.toml next to src/).
    while [[ "${crate_dir}" != "${ROOT}" && "${crate_dir}" != "/" ]]; do
        crate_dir="$(dirname "${crate_dir}")"
        if [[ -f "${crate_dir}/Cargo.toml" && -d "${crate_dir}/src" ]]; then
            break
        fi
    done
    if ! has_attack_test "${crate_dir}"; then
        echo "[lint] security claim without attack test: ${match}"
        errors=1
    fi
done < <(grep -REn --include='*.rs' -E 'attacker who|cannot forge' \
    "${ROOT}/shared/src" \
    "${ROOT}/vauban-auth/src" \
    "${ROOT}/vauban-audit/src" \
    "${ROOT}/vauban-access/src" \
    "${ROOT}/vauban-supervisor/src" \
    "${ROOT}/vauban-web/src" \
    "${ROOT}/vauban-vault/src" \
    2>/dev/null || true)

if [[ ${errors} -ne 0 ]]; then
    echo >&2
    echo "[lint] Every attacker/cannot-forge claim needs an attack_* / forged_* / *_is_rejected test." >&2
    echo "[lint] Opt out: // allow-untested-claim: <reason>" >&2
    exit 1
fi

echo "[lint] security claims are backed by attack tests (or explicitly opted out)"
