#!/usr/bin/env bash
# SSH-KEYAUTH -- structural lint: pin the SSH key-authentication redesign
# end-to-end paths. Companion of the RDP cert lint
# (`check_rdp_cert_paths.sh`) and the SSH host-key lint
# (`check_ssh_host_key_paths.sh`).
#
# Regressions guarded against forever:
#
# 1. (#4) A clear-text credential crossing the web -> proxy-ssh IPC. The
#    `SshSessionOpen` / `SshPushPublicKey` / `SshTestKeyAuth` wire
#    messages MUST carry only vault *ciphertexts*; the web `connect_ssh`
#    handler MUST NOT decrypt anything; the proxy MUST decrypt in its own
#    address space via the decrypt-only `VaultDecryptClient`.
#
# 2. Push / Test losing their MANDATORY host-key pinning pre-flight. We
#    authenticate by password (push) toward a potentially-spoofed host,
#    so an unpinned host could phish the one-shot password.
#
# Companion of:
#   - vauban-web/tests/web/ssh_key_auth_test.rs
#   - shared/src/messages.rs (SshSessionOpen / Push / Test round-trips)
#   - vauban-proxy-ssh/src/vault.rs (VaultDecryptClient unit tests)
#
# Returns non-zero on the first violation so it plugs into CI.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

errors=0

SHARED_MSG="${ROOT}/../shared/src/messages.rs"
WEB_SSH="${ROOT}/src/handlers/web/ssh.rs"
WEB_IPC="${ROOT}/src/ipc/proxy_ssh.rs"
PROXY_MAIN="${ROOT}/../vauban-proxy-ssh/src/main.rs"
PROXY_VAULT="${ROOT}/../vauban-proxy-ssh/src/vault.rs"

# Fixed-string / regex presence helpers that read from a here-string. We
# avoid `printf ... | grep -q` because `grep -q` closes the pipe on the
# first match; with `pipefail` the upstream `printf` then dies with
# SIGPIPE and the pipeline reports a false failure. Here-strings have no
# upstream process and so are immune.
has() { grep -qF -- "$1" <<<"$2"; }
hasE() { grep -qE -- "$1" <<<"$2"; }

require_file() {
    if [[ ! -f "$1" ]]; then
        echo "[lint] missing file: $1" >&2
        errors=1
        return 1
    fi
    return 0
}

# ---- 1. shared IPC enum: ciphertext-only wire format (#4) ----
if require_file "${SHARED_MSG}"; then
    shared_contents="$(cat "${SHARED_MSG}")"
    for field in password_ciphertext private_key_ciphertext passphrase_ciphertext; do
        if ! has "${field}" "${shared_contents}"; then
            echo "[lint] forbidden: ${SHARED_MSG} no longer defines \`${field}\`"
            echo "       #4: SshSessionOpen MUST carry vault ciphertexts, never"
            echo "       clear-text credentials."
            errors=1
        fi
    done
    for variant in SshPushPublicKey SshPushPublicKeyResult SshTestKeyAuth SshTestKeyAuthResult; do
        if ! has "${variant}" "${shared_contents}"; then
            echo "[lint] forbidden: ${SHARED_MSG} no longer defines \`${variant}\`"
            echo "       The push/test key-auth wire format would be broken."
            errors=1
        fi
    done
fi

# ---- 2. web connect_ssh: passes ciphertexts, never decrypts ----
if require_file "${WEB_SSH}"; then
    stripped_ssh="$(sed 's|//.*$||' "${WEB_SSH}")"
    # connect_ssh must forward the three ciphertexts read from config.
    for field in password_ciphertext private_key_ciphertext passphrase_ciphertext; do
        if ! has "${field}" "${stripped_ssh}"; then
            echo "[lint] forbidden: ${WEB_SSH} no longer references \`${field}\`"
            echo "       #4: connect_ssh must forward vault ciphertexts as-is."
            errors=1
        fi
    done
    # The web side decrypts NOTHING on the SSH credential path. The only
    # legitimate vault call here is the push handler ENCRYPTING the
    # one-shot password. A `.decrypt(` would resurrect the #4 hole.
    if hasE '\.decrypt\(' "${stripped_ssh}"; then
        echo "[lint] forbidden: ${WEB_SSH} calls \`.decrypt(\`"
        echo "       #4: web-side decryption is the hole this redesign closed."
        echo "       Credentials must be decrypted proxy-side via VaultDecryptClient."
        errors=1
    fi
    # Push / Test mandatory host-key pinning pre-flight.
    if ! has 'Pin the SSH host key first' "${stripped_ssh}"; then
        echo "[lint] forbidden: ${WEB_SSH} lost the mandatory host-key pre-flight"
        echo "       literal \"Pin the SSH host key first\" for push/test."
        echo "       Pushing a key by password to an unpinned host phishes it."
        errors=1
    fi
fi

# ---- 3. web IPC client: ciphertext request + push/test methods ----
if require_file "${WEB_IPC}"; then
    stripped_ipc="$(sed 's|//.*$||' "${WEB_IPC}")"
    if ! hasE 'fn[[:space:]]+push_public_key' "${stripped_ipc}"; then
        echo "[lint] forbidden: ${WEB_IPC} no longer exposes \`push_public_key\`."
        errors=1
    fi
    if ! hasE 'fn[[:space:]]+test_key_auth' "${stripped_ipc}"; then
        echo "[lint] forbidden: ${WEB_IPC} no longer exposes \`test_key_auth\`."
        errors=1
    fi
    if ! has 'expected_host_key' "${stripped_ipc}"; then
        echo "[lint] forbidden: ${WEB_IPC} no longer threads \`expected_host_key\`"
        echo "       through the request structs (host-key pinning)."
        errors=1
    fi
fi

# ---- 4. proxy-ssh decrypt-only Vault client exists ----
if require_file "${PROXY_VAULT}"; then
    vault_contents="$(cat "${PROXY_VAULT}")"
    if ! has 'struct VaultDecryptClient' "${vault_contents}"; then
        echo "[lint] forbidden: ${PROXY_VAULT} no longer defines \`VaultDecryptClient\`."
        echo "       #4: the proxy decrypts credentials in its own address space."
        errors=1
    fi
    if ! hasE 'DOMAIN_CREDENTIALS[[:space:]]*:[[:space:]]*&str[[:space:]]*=[[:space:]]*"credentials"' "${vault_contents}"; then
        echo "[lint] forbidden: ${PROXY_VAULT} DOMAIN_CREDENTIALS must equal \"credentials\""
        echo "       to match vauban-vault's authz allowlist (least privilege)."
        errors=1
    fi
fi

# ---- 5. proxy-ssh main wires the vault decrypt on every cred path ----
if require_file "${PROXY_MAIN}"; then
    stripped_main="$(sed 's|//.*$||' "${PROXY_MAIN}")"
    if ! has 'build_credential_via_vault' "${stripped_main}"; then
        echo "[lint] forbidden: ${PROXY_MAIN} no longer calls \`build_credential_via_vault\`"
        echo "       #4: SshSessionOpen credentials must be materialised by"
        echo "       decrypting the vault ciphertexts proxy-side."
        errors=1
    fi
    if ! hasE 'decrypt\(DOMAIN_CREDENTIALS' "${stripped_main}"; then
        echo "[lint] forbidden: ${PROXY_MAIN} no longer decrypts via DOMAIN_CREDENTIALS."
        errors=1
    fi
fi

if [[ ${errors} -ne 0 ]]; then
    echo >&2
    echo "[lint] One or more SSH key-auth invariants violated." >&2
    echo "[lint] See vauban-web/tests/web/ssh_key_auth_test.rs for the full" >&2
    echo "[lint] coverage matrix." >&2
    exit 1
fi

echo "[lint] SSH-KEYAUTH: key-auth paths intact (ciphertext-only IPC, no"
echo "[lint]            web-side decrypt, proxy VaultDecryptClient wired,"
echo "[lint]            push/test host-key pinning enforced)"
