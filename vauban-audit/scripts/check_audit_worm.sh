#!/usr/bin/env bash
# Structural lint: the audit service MUST durably persist every audit event to
# the tamper-evident WORM log BEFORE acknowledging it, and MUST fail closed.
#
# Regressions guarded against forever:
#
# 1. The pre-fix behavior where `handle_message`'s `AuditEvent` arm did
#    `info!` + `AuditAck` with a `// TODO: Write to WORM storage` and persisted
#    nothing. The TODO must never come back, and an `AuditAck` must only be
#    emitted AFTER a successful `WormLog::append_event`.
#
# 2. The fail-closed contract: a broker/open/write failure MUST send an
#    `AuditNack` (never a silent `AuditAck`) and bump the `events_failed`
#    anomaly counter.
#
# 3. The tamper-evidence primitives (BLAKE3 hash chain + Ed25519 segment seal)
#    staying wired into the WORM module.
#
# Companion of:
#   - vauban-audit/src/worm.rs (mod tests: chain / tamper / seal)
#   - vauban-audit/src/main.rs (mod tests: append+ack / fail-closed nack)
#   - shared/src/messages.rs   (AuditEventType COUNT drift test)
#
# Returns non-zero on the first violation so it plugs into CI. We read from
# here-strings (not `printf | grep -q`) to stay immune to the SIGPIPE false
# negative under `set -o pipefail`.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

errors=0

MAIN="${ROOT}/src/main.rs"
WORM="${ROOT}/src/worm.rs"

has() { grep -qF -- "$1" <<<"$2"; }

# ---- 1. worm.rs exists and carries the tamper-evidence primitives ----
if [[ ! -f "${WORM}" ]]; then
    echo "[lint] missing file: ${WORM}" >&2
    echo "       the WORM tamper-evident log module must exist." >&2
    exit 1
fi
stripped_worm="$(sed 's|//.*$||' "${WORM}")"

for token in 'fn append_event' 'fn seal' 'fn verify_reader' 'blake3::Hasher' 'SigningKey' 'sync_all' 'expected: &VerifyingKey' 'PubkeyMismatch' 'expected.to_bytes()' 'parse_pinned_verifying_key'; do
    if ! has "${token}" "${stripped_worm}"; then
        echo "[lint] forbidden: ${WORM} no longer references \`${token}\`"
        echo "       the WORM hash-chain / Ed25519 seal / out-of-band pin / fsync must stay intact."
        errors=1
    fi
done

# In-band pubkey must never be the sole VerifyingKey used to verify a seal.
if grep -nE 'VerifyingKey::from_bytes\(&pubkey_bytes\)' "${WORM}" | grep -v 'allow-inband-key:' >/dev/null; then
    echo "[lint] forbidden: ${WORM} builds VerifyingKey from the in-band seal pubkey"
    echo "       verify against the pinned expected key; compare pubkey_bytes to expected.to_bytes()."
    errors=1
fi

# ---- 2. main.rs wires the WORM module and persists before acking ----
if [[ ! -f "${MAIN}" ]]; then
    echo "[lint] missing file: ${MAIN}" >&2
    exit 1
fi
stripped_main="$(sed 's|//.*$||' "${MAIN}")"

# The pre-fix TODO must be gone.
if has 'TODO: Write to WORM' "${stripped_main}"; then
    echo "[lint] forbidden: ${MAIN} still carries the \`TODO: Write to WORM\` stub"
    echo "       the AuditEvent handler must persist to the WORM log, not no-op."
    errors=1
fi

for token in 'worm::' 'append_event' 'AuditNack' 'events_failed'; do
    if ! has "${token}" "${stripped_main}"; then
        echo "[lint] forbidden: ${MAIN} no longer references \`${token}\`"
        echo "       the persist-then-ack / fail-closed wiring is missing."
        errors=1
    fi
done

# A fail-closed handler sends AuditNack at least as often as it can fail: there
# must be at least two AuditNack sites (no-broker + append-error) and at least
# one AuditAck site.
nack_sites="$(grep -cF 'AuditNack' <<<"${stripped_main}" || true)"
if [[ "${nack_sites}" -lt 2 ]]; then
    echo "[lint] forbidden: only ${nack_sites} \`AuditNack\` site(s) in ${MAIN}"
    echo "       fail-closed requires a NACK on both the no-segment and write-error paths."
    errors=1
fi
if ! has 'AuditAck' "${stripped_main}"; then
    echo "[lint] forbidden: ${MAIN} no longer sends \`AuditAck\`"
    errors=1
fi

if [[ ${errors} -ne 0 ]]; then
    echo >&2
    echo "[lint] One or more audit WORM invariants violated." >&2
    echo "[lint] See vauban-audit/src/worm.rs and the tests in" >&2
    echo "[lint] vauban-audit/src/main.rs for the full coverage." >&2
    exit 1
fi

echo "[lint] audit WORM intact (hash chain + Ed25519 seal + fsync durability,"
echo "[lint]       persist-then-ack, fail-closed AuditNack on write failure,"
echo "[lint]       no TODO stub)"
