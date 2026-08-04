# Architecture Review — VCP Storage Helper 1.1

**Document reviewed:** `VCP_Storage_Helper_Architecture_EN(1.1).md` (version 1.1, 2026-08-04)
**Review date:** 2026-08-04
**Follow-up (2026-08-04):** Recommendations addressed in
[`VCP_Storage_Helper_Architecture_EN(1.2).md`](../../docs/technical/VCP_Storage_Helper_Architecture_EN(1.2).md)
and ADRs
[002](../../docs/adr/002-storage-webauthn-ceremony-channel-c1.md),
[003](../../docs/adr/003-ctap2-enrol-revoke-asymmetry.md),
[004](../../docs/adr/004-webauthn-sign-count-policy.md).
This review text is retained as the assessment record.
**Purpose:** assessment of the 1.1 design (WebAuthn/CTAP2 verified inside `vcp-store`, `put_prepare`/`put_commit` split), strengths, residual weaknesses, and recommendations for a 1.2 revision.

---

## 1. Overall verdict

The 1.1 architecture is **remarkably well designed**. The threat model is honest (residual risks are named, not hidden), the structural decisions D10–D12 place trust exactly where it belongs, and the whole is consistent with the supply-chain protection goal: no release publication and no deletion without proof of human presence, verified inside the smallest auditable component.

The weaknesses identified below are mostly specification and runbook refinements, not redesigns. The only substantive issue is the **presence vs. informed consent** distinction in the C1 ceremony channel (§3.1), which can be addressed without any architectural change.

---

## 2. Strengths

### 2.1 D10 — `vcp` untrusted for sensitive mutations

Making `vcp-store` the WebAuthn Relying Party is the correct TCB placement, and a rare choice. Most architectures verify the WebAuthn assertion inside the web application itself — which protects against nothing if that application is compromised. Here:

- peercred only proves UID 800;
- the assertion proves human presence, verified inside the sandboxed helper;
- a compromised `vcp` can speak the IPC but cannot materialize a release or delete an object without a valid ceremony.

This is the core value of 1.1.

### 2.2 Digest binding (§6.2) — the "sign then swap" attack is closed

The challenge is bound to the digest **computed by the helper** in `put_prepare`, from its own duplicated FD (`fstat` + full SHA-256), not to the digest announced by the client. A compromised `vcp` therefore cannot have the admin sign one content and substitute the package before the `renameat`. The invariant "the signed manifest must contain the hash of the actual content" is implemented in the right place: in the component that owns the file.

### 2.3 D12 — enrollment/revocation asymmetry

An excellent trade-off:

- **ACTIVE enrollment only via CLI on the helper host** → a compromised `vcp` cannot inject an attacker key (E2 is out of its reach).
- **Revocation via dashboard without CLI** → a compromised `vcp` can at worst cause operational DoS (revoking legitimate keys), never an escalation.

Fail-secure in the dangerous direction, fail-safe in the benign one. Many designs make these two flows symmetric and get it wrong.

### 2.4 Other solid points

- **One-shot challenges + TTL + structured binding** `{op, ids, digest, exp}`: anti-replay and anti-operation-confusion.
- **Privilege separation**: UID 800/801, `blob_path` at `0700`, best-effort Capsicum with a portable baseline (D5: security never depends on Capsicum alone).
- **SQLite SoT + verify-on-read**: a forged Postgres mirror or a tampered blob on disk fails cleanly (`integrity_mismatch`).
- **Images ungated on upload, gated on delete**: consistent with the threat model — the supply-chain asset is the releases.
- **Test pyramid covering negative cases**: binding mismatch, revoked credential, commit without assertion denied, bypass limited to testing.
- **Closed error set**: an auditable protocol surface.

---

## 3. Weaknesses and recommendations

### 3.1 Main weakness — C1 proves presence, not informed consent

The document mentions "Live MITM of admin ceremony (C1) — residual," but the actual risk is more precise than MITM:

The binding guarantees that an assertion is only valid for the exact challenge issued by the helper. But **the admin only sees the meaning of the operation through the UI served by `vcp`**, and WebAuthn offers no practically usable "transaction display" (the authenticator shows nothing about what is being signed). A compromised `vcp` can therefore initiate an operation that is legitimate from the helper's point of view (`delete_org` on org X) and dress the UI up as a benign action ("confirm deletion of a test image"). The admin touches their key, the assertion is valid, the binding holds — but the consent was deceived.

**Recommendations (without breaking C1):**

1. **Verifiable canonical summary**: the helper returns, along with each challenge, a short canonical summary (`op=delete_org org=acme`, truncated digest fingerprint for releases). The UI displays it, and for the most destructive operations the admin can cross-check it through an independent channel — for example a `vcp-store ctap2 pending` CLI subcommand on the helper host listing in-flight challenges with their bindings. Even if rarely used, this turns an invisible residual into a detectable risk.
2. **Helper-side audit log** of every challenge issued/consumed with its full binding, stored under `blob_path` (thus out of `vcp`'s reach), with alerting on destructive operations (`delete_org`, burst revocations).
3. **Keep C2** (a separate ceremony channel) as a documented evolution to harden this point if the need is confirmed.

### 3.2 `sign_count` policy undefined

The schema stores `sign_count` but the behavior on **counter regression** is not specified. A regression signals a cloned authenticator → rejection + alert recommended. Also note: **synced passkeys** (iCloud, Google) often report `0` permanently. For this supply-chain use case, requiring **hardware-bound keys** (via the attestation policy at enrollment) would be consistent; failing that, explicitly document the acceptance of synced passkeys and its consequences (the counter becomes useless as a cloning signal).

### 3.3 `userVerification` not specified

For operations at this level, `userVerification: required` (PIN or biometrics, not just presence/UP) should be:

- explicit in the helper configuration (`vcp-store.conf`);
- checked helper-side in the UV flag of the `authenticatorData` at verify time.

Without it, a key sitting on a desk and merely tapped is enough — too low a bar for `delete_org`.

### 3.4 Weak link in enrollment: substitution between E1 and E2

The document says "Compromised `vcp` must not be able to complete E2," but does not specify **what the operator verifies** at `ctap2 approve` time. The PENDING artifact transits through the portal (`vcp`'s database): a compromised `vcp` could **substitute the PENDING credential between E1 and E2**, and the operator would approve the attacker's key while believing they are approving the admin's.

**Recommendation:** mandate the comparison of a **credential fingerprint** (hash of `credential_id` + COSE public key):

- displayed at E1 in the portal, on the admin's side (they write it down or photograph it);
- **independently recomputed by the CLI** from the pending artifact at approve time;
- the operator approves only if both match (fingerprint transmitted out-of-band: verbally, over a separate messaging channel, etc.).

This is the most important point of this review after §3.1: without this verification, D12's central guarantee rests on an implicit, untooled assumption.

### 3.5 Purge of expired challenges

TTL purge is specified for `tmp/<upload_id>.partial` but not for the `webauthn_challenges` table. Trivial, but worth pinning: a purge job (or opportunistic cleanup on each `challenge_begin`) prevents accumulation and keeps the table auditable.

### 3.6 Production configuration guardrail

The `webauthn_required = false` bypass is necessary for CI, but nothing formally prevents this flag from leaking into production. **Recommendation:** boot-time validation in the helper that **refuses to start** if `webauthn_required = false` while the environment is `production`, plus an invariant test in the pyramid verifying that refusal. This is exactly in the spirit of the project's existing invariant tests.

### 3.7 Recovery and breakglass undocumented

`meta.sqlite` is the SoT, including for WebAuthn credentials. Two scenarios to cover in a runbook:

- **File loss/corruption**: backup strategy for `meta.sqlite` (objects can be re-hashed from disk; credentials cannot — they are irreplaceable without re-enrollment).
- **Loss of all admin keys**: the recovery path is implicitly the CLI on the helper host (direct E2 re-enrollment). This is acceptable — access to the helper host is already the root of trust — but it must be stated explicitly: it is the official breakglass, and it must be logged.

### 3.8 Delete / re-upload race (minor)

The `delete` challenge carries no digest ("object may already be gone from a race"). Consequence: an admin can sign the deletion of a `release_id` whose **content was replaced** between the ceremony and execution — deleting something other than what they believed they approved.

**Optional recommendation:** bind the challenge to the current `sha256` when it exists, with an explicit failure if the digest changed at execution time ("the object was modified since the request; start over"). Cost: a benign failure in the race case. Benefit: consent applies to a precise content, consistent with the digest-binding philosophy of §6.2.

---

## 4. Summary of recommendations for 1.2

| # | Topic | Priority | Nature |
|---|-------|----------|--------|
| 3.1 | Canonical binding summary + helper audit log + `ctap2 pending` CLI | **High** | Informed consent (C1 residual) |
| 3.4 | Credential fingerprint verified at E2 (approve) | **High** | Closes the PENDING E1→E2 substitution |
| 3.3 | `userVerification: required` explicit and enforced | **High** | One config line + one UV check |
| 3.6 | Boot refusal if WebAuthn bypass in production | Medium | Config guardrail + invariant test |
| 3.2 | `sign_count` policy (regression, synced passkeys) | Medium | Specification + attestation policy |
| 3.7 | `meta.sqlite` backup runbook + documented breakglass | Medium | Operational documentation |
| 3.5 | `webauthn_challenges` purge | Low | Hygiene |
| 3.8 | Optional delete binding to current digest | Low | Consent consistency |

None of these recommendations calls the architecture into question: D10 (helper = RP), D11 (C1 channel), and D12 (enrollment/revocation asymmetry) are the right decisions and should be kept as is.

---

## 5. Bottom line

1.1 correctly raises the TCB for release publication and deletions: a human with a CTAP2 credential activated out of the portal's reach becomes mandatory, and digest binding guarantees that what is signed is what is published. The two real work items for 1.2 are (a) closing the gap between proven **presence** and actually given **consent** (§3.1), and (b) tooling the human verification of the enrollment flow (§3.4). The rest is fine-grained specification and runbooks. As it stands, the design is sign-off ready.
