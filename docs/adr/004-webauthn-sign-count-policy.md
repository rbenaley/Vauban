# ADR 004: WebAuthn sign_count policy for storage CTAP2

**Status:** Accepted  
**Date:** 2026-08-04  
**Related:**
[`VCP_Storage_Helper_Architecture_EN(1.2).md`](../technical/VCP_Storage_Helper_Architecture_EN(1.2).md)
(D14, §6.7),
`webauthn_strict_sign_count` in `vcp-store.conf`,
[storage 1.1 architecture review](../../.cursor/audits/vcp_storage_1.1_architecture_review_2026-08-04.md)
(§3.2)

## Context

WebAuthn `sign_count` can detect cloned authenticators when the counter
monotonically increases (typical of many hardware security keys). Synced
platform passkeys (Apple iCloud Keychain, Google Password Manager, Mac
Touch ID platform passkeys in the common case) often report **`sign_count = 0`
permanently**, so counter regression is not a usable cloning signal.

Requiring hardware-bound keys only would exclude convenient admin devices.
Ignoring counters entirely would weaken fleets that standardize on YubiKeys.

## Decision

1. **Default: `webauthn_strict_sign_count = false`.** Synced / platform
   passkeys with a stuck-at-zero counter are **accepted**. The helper still
   stores the last seen counter when the authenticator reports a non-zero
   value.
2. **Opt-in strict mode: `webauthn_strict_sign_count = true`.** If the stored
   counter is non-zero and a new assertion presents a **lower** counter, the
   helper **rejects** the assertion (`webauthn_invalid`), writes an audit
   event, and **alerts**. Intended for deployments that require hardware-bound
   authenticators.
3. **Attestation-enforced hardware-only enrolment is not required** for MVP.
   Operators who need that bar use strict mode plus operational policy
   (which authenticators they enrol), or a future ADR for attestation
   filters at `ctap2 approve`.
4. **`userVerification: required` remains mandatory** regardless of this flag
   (architecture D13); strict sign_count is orthogonal to UV.

## Consequences

- Architecture and conf templates ship `webauthn_strict_sign_count = false`.
- Tests cover both: default accepts `sign_count=0`; strict rejects regression.
- Docs must not claim clone detection for Touch ID / iCloud-style passkeys
  under the default policy.
