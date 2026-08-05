# ADR 002: Storage WebAuthn ceremony channel (C1)

**Status:** Accepted  
**Date:** 2026-08-04  
**Related:**
[`VCP_Storage_Helper_Architecture_EN(1.2).md`](../technical/VCP_Storage_Helper_Architecture_EN(1.2).md)
(D11, §6.6),
[storage 1.1 architecture review](../../.cursor/audits/vcp_storage_1.1_architecture_review_2026-08-04.md)
(§3.1)

## Context

Sensitive storage mutations (release finalize, deletes) require WebAuthn
assertions verified inside `vcp-store` (D10). The browser cannot speak the
helper Unix socket directly. Two ceremony channels were considered:

- **C1** — browser ↔ portal `vcp` ↔ helper IPC (relay).
- **C2** — separate HTTPS surface / jail that is not the compromised-portal
  process, used only for challenge presentation and assertion collection.

C1 is simpler to ship but proves **presence**, not **informed consent**: a
compromised `vcp` can dress a destructive op (`delete_org`) as a benign UI
while the helper binding remains cryptographically valid for the real op.

## Decision

1. **MVP and near-term production use C1.**
2. **1.2 mitigations are mandatory**, not optional UX polish:
   - helper returns a canonical `summary` with every challenge;
   - portal UI must display that summary;
   - `vcp-store key pending` lists in-flight challenges on the helper host;
   - helper audit log under `blob_path` records issue/consume of challenges.
3. **C2 is an accepted future hardening**, not scheduled in the 1.2
   implementation train. A new ADR (or amend of this one) is required before
   building a second ceremony HTTPS service.

## Consequences

- Design reviews do not block on C2 for the first WebAuthn-gated release.
- Residual "deceived consent under compromised `vcp`" remains documented in
  the 1.2 threat model; operators may use `key pending` for high-risk ops.
- Introducing C2 later must preserve digest/op binding and helper-side verify;
  it must not move assertion verification back into `vcp`.
