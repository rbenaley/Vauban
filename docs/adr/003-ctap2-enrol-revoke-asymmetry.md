# ADR 003: CTAP2 enrolment / revocation asymmetry

**Status:** Accepted  
**Date:** 2026-08-04  
**Related:**
[`VCP_Storage_Helper_Architecture_EN(1.2).md`](../technical/VCP_Storage_Helper_Architecture_EN(1.2).md)
(D12, §6.5),
[storage 1.1 architecture review](../../.cursor/audits/vcp_storage_1.1_architecture_review_2026-08-04.md)
(§2.3, §3.4)

## Context

WebAuthn credentials that authorize release publication and deletes are part
of the helper TCB (SQLite under UID 801). The Admin **CTAP2** dashboard runs
inside `vcp` (UID 800), which is **untrusted** for sensitive mutations (D10).

If enrolment finalize and revocation were both fully portal-driven, a
compromised `vcp` could inject an attacker ACTIVE key. If both required
helper-host CLI, day-2 revocation would be operationally heavy and slow
during incident response.

## Decision

1. **Enrolment is two-phase:** E1 web creates a PENDING artifact and shows a
   **credential fingerprint**; E2 `vcp-store ctap2 approve` on the helper host
   recomputes the fingerprint and activates the key only on out-of-band match.
   **Only E2** writes ACTIVE rows into helper SQLite.
2. **Revocation is dashboard-driven** (plus helper IPC `ctap2_revoke`) with
   **no** helper-host CLI requirement.
3. **Accepted residual:** compromised `vcp` may mass-revoke keys (ops DoS /
   lock-out) but **cannot** enrol new ACTIVE keys without CLI approve.
4. **Breakglass** after total key loss is re-enrolment via E1+E2 on the helper
   host, logged in the helper audit log (see architecture 1.2 §10).

## Consequences

- Product and security reviews treat "portal-only enrolment activate" as
  rejected unless this ADR is superseded.
- CTAP2 UI must surface fingerprints and CLI instructions; approve tooling
  must fail closed on fingerprint mismatch.
- Ops alerting SHOULD watch revoke bursts; recovery runbooks document
  breakglass CLI approve.
