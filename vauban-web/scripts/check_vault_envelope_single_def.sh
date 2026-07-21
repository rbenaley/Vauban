#!/usr/bin/env bash
# Lint guard: vault envelope shape predicate (I1 / I2 / I6).
#
# Why: architecture review §4.2 / reco §10.9 — the `v{digits}:…` classifier
# was copy-pasted across vault / web / supervisor and drifted. The grammar
# must live once in shared/src/vault_envelope.rs; other crates only thin-
# alias. vauban-web must NOT depend on vauban-vault just to classify shape
# (privsep / Capsicum surface).
#
# Checks:
#   1. shared/src/vault_envelope.rs exists with is_vault_envelope
#   2. algorithmic body (is_ascii_digit on version slice) only in that file
#   3. vauban-web/Cargo.toml does not list vauban-vault
#   4. web / vault / supervisor aliases call shared::vault_envelope

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WEB_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CANON="${ROOT}/shared/src/vault_envelope.rs"

fail=0

if [[ ! -f "${CANON}" ]]; then
    echo "[lint] missing ${CANON}" >&2
    exit 2
fi

# ---- 1. Canon must expose the load-bearing symbols -----------------------
for needle in "pub fn is_vault_envelope" "pub fn vault_envelope_version" "is_ascii_digit"; do
    if ! grep -q "${needle}" "${CANON}"; then
        echo "[lint] vault_envelope.rs must contain '${needle}'" >&2
        fail=1
    fi
done

# ---- 2. Algorithmic body only in shared ----------------------------------
# Unique signature of the envelope version scan (not MFA code digit checks):
#   value[1..colon_pos].chars().all(|c| c.is_ascii_digit())
while IFS= read -r hit; do
    file="${hit%%:*}"
    if [[ "${file}" == "${CANON}" ]]; then
        continue
    fi
    echo "[lint] duplicate envelope digit-scan outside shared: ${hit}" >&2
    fail=1
done < <(
    grep -rn 'value\[1\.\.colon_pos\]\.chars()\.all(|c| c\.is_ascii_digit())' \
        "${ROOT}/shared/src" \
        "${ROOT}/vauban-web/src" \
        "${ROOT}/vauban-vault/src" \
        "${ROOT}/vauban-supervisor/src" \
        --include='*.rs' 2>/dev/null || true
)

# Broader catch: every is_encrypted* helper must eventually reach shared
# (direct call, or MFA alias that itself delegates to shared).
for crate_src in \
    "${ROOT}/vauban-web/src" \
    "${ROOT}/vauban-vault/src" \
    "${ROOT}/vauban-supervisor/src"; do
    while IFS= read -r hit; do
        file="${hit%%:*}"
        if grep -q "shared::vault_envelope::is_vault_envelope" "${file}"; then
            continue
        fi
        # handlers/auth.rs keeps a backward-compat alias that calls
        # is_encrypted_mfa_secret (which itself delegates to shared).
        if grep -q "is_encrypted_mfa_secret" "${file}"; then
            continue
        fi
        echo "[lint] envelope-shaped helper without shared delegation: ${hit}" >&2
        fail=1
    done < <(
        grep -rn "fn is_encrypted\|fn is_encrypted_mfa_secret\|fn is_vault_envelope" \
            "${crate_src}" --include='*.rs' 2>/dev/null || true
    )
done

# ---- 3. I6: web must not link vauban-vault --------------------------------
WEB_CARGO="${WEB_ROOT}/Cargo.toml"
if grep -qE '^\s*vauban-vault\s*=' "${WEB_CARGO}"; then
    echo "[lint] vauban-web/Cargo.toml must NOT depend on vauban-vault (I6)" >&2
    fail=1
fi

# ---- 4. Aliases must point at shared -------------------------------------
for f in \
    "${ROOT}/vauban-vault/src/keyring.rs" \
    "${ROOT}/vauban-web/src/services/auth.rs" \
    "${ROOT}/vauban-web/src/handlers/web/mod.rs" \
    "${ROOT}/vauban-web/src/ipc/admin.rs" \
    "${ROOT}/vauban-supervisor/src/admin.rs"; do
    if [[ ! -f "${f}" ]]; then
        echo "[lint] missing expected alias file ${f}" >&2
        fail=1
        continue
    fi
    if ! grep -q "shared::vault_envelope::is_vault_envelope" "${f}"; then
        echo "[lint] ${f} must delegate to shared::vault_envelope::is_vault_envelope" >&2
        fail=1
    fi
done

if [[ "${fail}" -ne 0 ]]; then
    echo "[lint] check_vault_envelope_single_def FAILED" >&2
    exit 1
fi

echo "[lint] check_vault_envelope_single_def OK"
exit 0
