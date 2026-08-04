# VCP `storage/` — Sandboxed helper process (design & architecture)

**Version:** 1.2  
**Date:** 2026-08-04  
**Status:** design — supersedes
[`VCP_Storage_Helper_Architecture_EN(1.1).md`](VCP_Storage_Helper_Architecture_EN(1.1).md);
addresses
[`.cursor/audits/vcp_storage_1.1_architecture_review_2026-08-04.md`](../../.cursor/audits/vcp_storage_1.1_architecture_review_2026-08-04.md).
The 1.0 helper + SQLite digest SoT remain shipped; 1.1 introduced
helper-side WebAuthn/CTAP2 gates; **1.2 hardens consent, enrolment,
UV, sign-count policy, delete binding, purge, and ops breakglass**.  
**Scope:** on-disk storage under a helper-owned root (`blob_path` in
`vcp-store.conf`) for **release artifacts** and **tenant images**, served by
`vcp-store` (Capsicum on FreeBSD; soft fence elsewhere). Digests SoT =
SQLite `meta.sqlite`; Postgres `storage_objects` = portal mirror.  
**Reference:** audit `vcp_capsicum_storage_sandbox_2026-08-02.md`; UIDs
`vcp`=**800**, `vcp-storage`=**801**. Related ADRs: [002](../adr/002-storage-webauthn-ceremony-channel-c1.md),
[003](../adr/003-ctap2-enrol-revoke-asymmetry.md),
[004](../adr/004-webauthn-sign-count-policy.md).

### Changelog from 1.1 (review mapping)

| Review | 1.2 change |
|--------|------------|
| §3.1 Presence vs consent | Canonical challenge `summary`; UI must display it; `vcp-store ctap2 pending`; helper audit log under `blob_path`; ops alerts on `delete_org` / revoke bursts. C2 deferred → ADR 002 |
| §3.4 E1→E2 substitution | Mandatory credential **fingerprint** at E1 and CLI approve |
| §3.3 userVerification | `webauthn_user_verification = "required"`; UV flag checked at verify |
| §3.6 Bypass in prod | Boot refuses `webauthn_required=false` when production |
| §3.2 sign_count | Synced passkeys OK by default; `webauthn_strict_sign_count` opt-in → ADR 004 |
| §3.7 Backup / breakglass | Ops: joint backup; CLI re-enrol is official breakglass (logged) |
| §3.5 Challenge purge | TTL purge of `webauthn_challenges` |
| §3.8 Delete race | Delete challenge binds current SoT `sha256` when object exists; `object_modified` if changed |

---

## 1. Structural decisions

| # | Decision | Rationale |
|---|----------|-----------|
| D1 | **Helper process** `vcp-store`; no Capsicum on `vcp` | `cap_enter(2)` is process-wide; ACME/TLS stay in `vcp` |
| D2 | OS users: portal **`vcp` UID 800**; helper **`vcp-storage` UID 801**; `blob_path` `0700` | Compromised portal UID must not open blobs by path |
| D3 | Control plane IPC + data plane `SCM_RIGHTS` | Throughput; per-FD rights |
| D4 | Best-effort Capsicum on FreeBSD; WARN elsewhere | Same product behavior; kernel fence where available |
| D5 | Portable baseline: dirfd, `openat`, opaque IDs, umask 077 | Security never depends on Capsicum alone |
| D6 | Synchronous helper; sync `rusqlite` only | Small audit surface |
| D7 | **Casbin / sessions / org membership stay in `vcp`** for HTTP UX and IDOR | Helper still has no portal sessions |
| D8 | Two families, one I/O mechanism (`releases/` + `images/`) | One audited path |
| D9 | Digest SoT = SQLite; Postgres = mirror; `get`/`stat` present expected sha256 + verify-on-read | Forged mirror / tampered disk fail closed |
| **D10** | **For sensitive mutations, `vcp` is untrusted:** WebAuthn assertions are **verified inside `vcp-store`** before materializing release packages or performing deletes | Peercred only proves UID 800 |
| **D11** | Ceremony channel **C1** (browser ↔ `vcp` ↔ helper); mitigations for informed consent in §6.6; **C2 deferred** ([ADR 002](../adr/002-storage-webauthn-ceremony-channel-c1.md)) | MVP without a second HTTPS surface |
| **D12** | **CTAP2** Admin UI: enrolment pending in portal; **ACTIVE only via helper-host CLI**; **revocation via dashboard** ([ADR 003](../adr/003-ctap2-enrol-revoke-asymmetry.md)) | Fail-secure on enrol; accept revoke-DoS |
| **D13** | **`userVerification: required`** enforced helper-side | PIN/biometric, not presence-only tap |
| **D14** | **`sign_count`**: default permissive (synced passkeys); optional strict regression policy ([ADR 004](../adr/004-webauthn-sign-count-policy.md)) | Touch ID / iCloud / GPM keep counter at 0 |

---

## 2. Architecture

```text
                 ┌─────────────────────────────────────────────┐
                 │  vcp (UID 800)                              │
                 │  HTTPS · Casbin · sessions · ACME · DB      │
                 │  Postgres mirror + CTAP2 pending UX         │
                 │  WebAuthn ceremony relay (C1) + summary UI  │
                 └────────┼────────────────────────────────────┘
                          │  SOCK_SEQPACKET + SCM_RIGHTS
                          │  + WebAuthn assertion on gated ops
                 ┌────────▼────────────────────────────────────┐
                 │  vcp-store (UID 801 / vcp-storage)          │
                 │  digests SoT (meta.sqlite)                  │
                 │  WebAuthn RP verify + challenges + audit log│
                 │  Capsicum (FreeBSD) / soft fence            │
                 └────────┬────────────────────────────────────┘
                          │ openat(dirfd) only
                 ┌────────▼────────────────────────────────────┐
                 │  blob_path/  (vcp-storage:vcp-storage, 0700)│
                 │    meta.sqlite   # objects + webauthn_*     │
                 │    audit/webauthn.log  (or sqlite audit)    │
                 │    releases/<release_id>.pkg                │
                 │    images/<org_id>/<image_id>.<ext>         │
                 │    tmp/<upload_id>.partial                  │
                 └─────────────────────────────────────────────┘
```

Helper-host CLI:

```text
vcp-store ctap2 pending          # PENDING credentials (E2) + in-flight challenges/summaries
vcp-store ctap2 list             # all credentials (pending / active / revoked)
vcp-store ctap2 approve …        # E2: activate credential after fingerprint match
```

---

## 3. Configuration

### 3.1 Portal — `vcp.conf` `[storage]` (production)

```toml
[storage]
ipc = "socket"
socket_path = "/var/run/vcp/store.sock"
```

No `blob_path` in production portal config.

### 3.2 Helper — `vcp-store.conf` (production)

```toml
blob_path = "/var/db/vcp/storage"
listen = "/var/run/vcp/store.sock"
expected_peer_uid = 800
max_artifact_bytes = 2147483648
max_image_bytes = 10485760
allowed_image_types = ["png", "jpeg", "webp"]
max_concurrent_uploads = 4
max_images_per_org = 1000
upload_ttl_secs = 3600

# WebAuthn / CTAP2 (Relying Party inside the helper)
webauthn_required = true
webauthn_user_verification = "required"
webauthn_strict_sign_count = false   # true => reject + alert on counter regression
webauthn_rp_id = "access.vauban.sh"
webauthn_origin = "https://access.vauban.sh"
webauthn_challenge_ttl_secs = 300
webauthn_pending_ttl_hours = 24   # PENDING enrol → expired if not approved; 0 = off
```

Also present under portal `[storage]` (`default.toml` / `development.toml`) so
spawn/dev and `vcp-store ctap2` with `VCP_ENVIRONMENT=development` share the
same knob without reading `vcp-store.conf`.

**Production boot guard:** if the helper is started with `--production` (or
equivalent production mode) and `webauthn_required = false`, **refuse to
start**. Testing may set `webauthn_required = false` only outside production.
Pyramid invariant: production conf / boot path never allows the bypass.

### 3.3 Development / testing

| Env | IPC | `webauthn_required` |
|-----|-----|---------------------|
| development (`spawn`) | spawn | **true** (functional validation) |
| testing (`inline`) | inline | **false** (CI bypass) |
| production | socket | **true** (enforced at boot) |

---

## 4. Helper lifecycle and boot

1. `umask(077)`; open `blob_path` dirfd; mkdir `releases/`, `images/`, `tmp/`,
   and audit dir if file-based.
2. Open/migrate **`meta.sqlite`** (objects + **webauthn_credentials** +
   **webauthn_challenges** [+ optional audit table]) **before** `cap_enter`.
3. Load WebAuthn RP config; **fail** if production and
   `webauthn_required=false`.
4. Bind listen socket; Capsicum / WARN; accept + `expected_peer_uid` (800).
5. Opportunistic purge of expired `webauthn_challenges`, stale PENDING
   enrolments (`webauthn_pending_ttl_hours` → status `expired`), and
   `tmp/*.partial` (same TTL spirit).

`vcp-store ctap2 …` subcommands run as a **separate invocation** that can
write SQLite / read pending challenges outside the sandboxed accept loop as
needed for ops.

---

## 5. Storage layout and digests

- SoT: `meta.sqlite` → `objects` (`scope`, `object_key`, `org_id`, `sha256`,
  `size_bytes`, …).
- Mirror: Postgres `storage_objects` (portal only).
- **Overwrite:** successful commit for an existing release or image path =
  atomic `renameat` + SQLite upsert (+ Postgres mirror by `vcp`).
- Image `object_key`: `{org_id}/{image_id}.{ext}`.

```text
webauthn_credentials
  credential_id   BLOB PRIMARY KEY
  public_key_cose BLOB NOT NULL
  user_handle     TEXT NOT NULL
  admin_label     TEXT NOT NULL
  sign_count      INTEGER NOT NULL
  created_at      INTEGER NOT NULL
  revoked_at      INTEGER NULL

webauthn_challenges
  challenge_id    TEXT PRIMARY KEY
  op              TEXT NOT NULL
  binding_json    TEXT NOT NULL        -- includes digest when applicable
  summary         TEXT NOT NULL        -- canonical human-readable line
  expires_at      INTEGER NOT NULL
  consumed_at     INTEGER NULL
```

**Credential fingerprint** (enrolment):

```text
fingerprint = hex(SHA-256(credential_id || public_key_cose))
```

Displayed at E1; independently recomputed by `ctap2 approve` before ACTIVE
insert.

**Audit log** (under `blob_path`, not writable by UID 800): every challenge
issued/consumed with full binding + summary; every verify success/failure;
every revoke; every `ctap2 approve`. Ops SHOULD alert on `delete_org` and on
bursts of `ctap2_revoke`.

---

## 6. WebAuthn / CTAP2 (D10–D14)

### 6.1 When the helper requires WebAuthn

| Operation | Release | Image |
|-----------|---------|-------|
| `put_begin` / FD write | no | no |
| `put_prepare` + `put_commit` + assertion | **yes** | — (image commit **no** WebAuthn) |
| Overwrite via successful commit | **yes** (release) | no WebAuthn |
| `delete` | **yes** | **yes** |
| `delete_org` | — | **yes** |
| `get` / `stat` | no | no |

### 6.2 Gated release upload

```text
put_begin → write FD → put_prepare → (C1 ceremony) → put_commit+assertion
```

1. **`put_begin` / write** — data plane; no WebAuthn.
2. **`put_prepare`** (release) — helper hashes its FD; compares client
   expected sha256; **no** `renameat`; emits one-shot challenge bound to
   `{op=release_put_commit, release_id, upload_id, digest, exp}` plus
   **`summary`** (e.g. `release_put_commit id=42 sha256=abcd1234…`); returns
   `{digest, challenge, summary, rp_id, allowCredentials}`.
3. **Ceremony (C1)** — portal **must display `summary`** prominently before
   `credentials.get`; admin may cross-check via `vcp-store ctap2 pending`.
4. **`put_commit`** — verify assertion: COSE, ACTIVE cred, UV required,
   challenge consume, binding including helper digest, sign_count policy
   (§6.7); then rename + SQLite upsert. Mirror upsert in `vcp` afterward.

### 6.3 Deletes (digest-bound when object exists)

```text
challenge_begin → ceremony → delete*|delete_org + assertion
```

Binding:

- `delete` release: `{op, scope=release, release_id, sha256?}` — **`sha256`
  required when a SoT row exists** at challenge time.
- `delete` image: `{op, scope=image, org_id, image_id, ext, sha256?}`.
- `delete_org`: `{op=delete_org, org_id}` (no single-object digest).

At execution: if binding included `sha256` and the current SoT digest differs
(or the row vanished when a digest was bound) → **`object_modified`** (or
equivalent closed code); admin must start over. If the object was already
absent and challenge was issued without digest (gone before challenge),
delete is idempotent success after valid assertion.

`summary` examples: `delete release id=42 sha256=abcd1234…`,
`delete_org org_id=9`.

### 6.4 Verify checks (every gated assertion)

1. Credential ACTIVE (`revoked_at` IS NULL).
2. Signature valid (COSE) over clientData/authenticatorData.
3. `webauthn_user_verification = "required"` → UV flag set in
   `authenticatorData`.
4. Challenge unconsumed, unexpired, binding match.
5. `sign_count` policy (§6.7).
6. Consume challenge; append audit line.

### 6.5 CTAP2 admin dashboard (portal)

- Sidebar **CTAP2** under **Orgs**; Casbin-gated; non-staff **404**.
- Per-admin keys (model B).

#### Enrolment (two-phase) — fingerprint mandatory

| Phase | Where | Effect |
|-------|-------|--------|
| E1 Web | `/admin/ctap2` | `credentials.create`; PENDING in portal DB; show **fingerprint** + CLI instructions; admin records fingerprint out-of-band |
| E2 CLI | Helper host | `vcp-store ctap2 approve` recomputes fingerprint from artifact; operator confirms OOB match; only then INSERT ACTIVE |

Without fingerprint match, approve **must fail**. Compromised `vcp` cannot
complete E2.

#### Revocation

Dashboard + IPC `ctap2_revoke` only (no helper CLI). Audit + alert on bursts.
Compromise of `vcp` may DoS via mass revoke; cannot enrol ACTIVE keys
([ADR 003](../adr/003-ctap2-enrol-revoke-asymmetry.md)).

### 6.6 Informed consent mitigations (C1 residual)

WebAuthn proves **presence**, not that the admin read the true op. Mitigations
normative in 1.2:

1. Helper returns **canonical `summary`** with every challenge; portal UI
   **must** show it (not only a soft label invented by `vcp`).
2. **`vcp-store ctap2 pending`** lists PENDING credentials awaiting E2
   approve (fingerprint / label) **and** in-flight ceremony challenges with
   bindings / summaries for independent check on the helper host.
3. **Helper audit log** under `blob_path` (out of UID 800 write reach).

Hardening to a separate ceremony channel (**C2**) is deferred
([ADR 002](../adr/002-storage-webauthn-ceremony-channel-c1.md)).

### 6.7 `sign_count` policy

- **Default** (`webauthn_strict_sign_count = false`): accept authenticators
  that keep `sign_count` at 0 (iCloud Keychain, Google Password Manager,
  Touch ID platform passkeys, etc.). Still store the last seen counter when
  non-zero.
- **Strict** (`webauthn_strict_sign_count = true`): if stored counter is
  non-zero and the assertion counter **regresses**, reject
  (`webauthn_invalid`), audit, and **alert**. Intended for fleets that
  standardize on hardware-bound keys (e.g. YubiKey).

See [ADR 004](../adr/004-webauthn-sign-count-policy.md).

### 6.8 Error codes (closed set additions)

`webauthn_required`, `webauthn_invalid`, `webauthn_expired`,
`challenge_unknown`, `object_modified`, plus existing
`not_found`, `invalid_id`, `quota`, `org_quota`, `bad_image`,
`digest_mismatch`, `integrity_mismatch`, `io`, `busy`.

---

## 7. IPC protocol

| Request | Response | FD | WebAuthn |
|---------|----------|----|----------|
| `get` / `stat` + `sha256` | ok or `integrity_mismatch` | get: read | no |
| `put_begin` | ok `upload_id` | write | no |
| `put_prepare` (release) | ok `digest`, `challenge`, `summary`, … | — | emits challenge |
| `put_commit` (release) + assertion | ok size/sha256 | — | **verify** |
| `put_commit` (image) | ok size/sha256 | — | no |
| `put_abort` | ok | — | drops related challenge |
| `challenge_begin` (delete*) | ok `challenge`, `summary`, … | — | emits challenge |
| `delete` + assertion | ok or `object_modified` | — | **verify** |
| `delete_org` + assertion | ok `deleted` | — | **verify** |
| `ctap2_revoke` | ok | — | no |

Control JSON remains under 4 KiB; enrolment attestation blobs stay in portal
PENDING storage for E1.

Data plane download / image upload / release prepare path as in 1.1, with
§6.2–6.3 amendments.

---

## 8. Capsicum and portable hardening

As in 1.0/1.1, plus: WebAuthn verify and audit append use already-open
resources under `blob_path`; no outbound network from the helper for
WebAuthn.

---

## 9. Threat model (digest + WebAuthn)

| Threat | Mitigation |
|--------|------------|
| Forged Postgres mirror digest | verify-on-read / `integrity_mismatch` |
| Tampered blob on disk | re-hash vs SQLite |
| Compromised `vcp` opens `blob_path` | UID 801 + 0700 |
| Compromised `vcp` calls IPC without human | WebAuthn + UV on release finalize + deletes |
| Compromised `vcp` swaps package after ceremony | Challenge bound to **helper digest** |
| Compromised `vcp` substitutes PENDING enrol key | Fingerprint OOB check at CLI approve |
| Compromised `vcp` deceives UI meaning (C1) | Canonical `summary` + `ctap2 pending` + audit; residual → ADR 002 / C2 |
| Compromised `vcp` revokes keys | Accepted residual (ADR 003) |
| Delete after content replace | Digest binding + `object_modified` |
| Synced passkey cloning | Not detected when counter stays 0; strict mode for HW keys (ADR 004) |

---

## 10. Ops: backup, purge, breakglass

- **Backup:** always back up `meta.sqlite` **together with** `blob_path`.
  Blobs can be re-hashed into `objects`; **WebAuthn credentials cannot** —
  loss requires re-enrolment.
- **Challenge purge:** delete rows with `expires_at < now` (and optionally
  old consumed rows) on `challenge_begin` / `put_prepare` and/or a periodic
  helper tick; same spirit as `tmp/*.partial` TTL.
- **PENDING enrolment TTL:** `webauthn_pending_ttl_hours` (default 24; `0`
  disables). Unapproved `status=pending` rows with `created_at` older than
  the TTL become `status=expired` (row kept for ops history; not approvable).
  Runs on helper open and on CTAP2 list / pending / approve / enrol paths.
- **Breakglass (loss of all admin keys):** official path is physical/ops
  access to the helper host and CLI `ctap2 approve` of new enrolments (E2),
  after E1 from a trusted admin session or emergency procedure. **Every
  breakglass approve MUST be logged** in the helper audit log. Access to
  the helper host remains the root of trust for credential SoT.

---

## 11. Tests (1.2 additions on top of 1.1 pyramid)

- UV missing → reject; summary present on challenge responses.
- Fingerprint mismatch → `ctap2 approve` fails.
- `object_modified` when delete digest drifted.
- Production boot refuses `webauthn_required=false`.
- `webauthn_strict_sign_count=true` + counter regression → reject + audit.
- Default strict=false accepts assertion with `sign_count=0`.
- Challenge table purge removes expired rows.
- Invariants pin doc 1.2 + ADR links + conf knobs.

---

## 12. Implementation plan

| Phase | Content |
|-------|---------|
| A | Docs 1.2 + ADR 002–004 (this revision) |
| B | Protocol/types + conf knobs + SQLite webauthn_* + UV/sign_count/purge |
| C | Release prepare/commit + summary UI (C1) |
| D | Delete / delete_org with digest binding |
| E | CTAP2 dashboard + fingerprint + CLI approve/pending + revoke IPC |
| F | Audit log, alerts, runbooks, breakglass drill |

---

## 13. Bottom line

**1.2** keeps D10–D12 and closes the review gaps that matter before coding:
helpers emit **verifiable summaries** and audit trails, enrolment activate
requires a **fingerprint match**, **UV is mandatory**, production cannot
disable WebAuthn, **deletes bind content digests**, challenges are purged,
and breakglass is explicit. Synced platform passkeys remain usable by
default; fleets that want counter-based clone detection opt into
`webauthn_strict_sign_count`.
