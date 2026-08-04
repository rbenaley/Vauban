# VCP `storage/` — Sandboxed helper process (design & architecture)

**Version:** 1.1  
**Date:** 2026-08-04  
**Status:** design — supersedes
[`VCP_Storage_Helper_Architecture_EN(1.0).md`](VCP_Storage_Helper_Architecture_EN(1.0).md);
implementation of the 1.0 helper + SQLite digest SoT is shipped; **1.1 adds
WebAuthn (CTAP2) gates verified inside `vcp-store`** and splits release
finalize into `put_prepare` / `put_commit`.  
**Scope:** on-disk storage under a helper-owned root (`blob_path` in
`vcp-store.conf`) for **release artifacts** and **tenant images**, served by
`vcp-store` (Capsicum on FreeBSD; soft fence elsewhere). Digests SoT =
SQLite `meta.sqlite`; Postgres `storage_objects` = portal mirror.  
**Reference:** audit `vcp_capsicum_storage_sandbox_2026-08-02.md`; UIDs
`vcp`=**800**, `vcp-storage`=**801**.

### Changelog from 1.0

| Topic | 1.0 | 1.1 |
|-------|-----|-----|
| Digest SoT | SQLite helper + verify-on-read | Unchanged |
| Config split | `vcp.conf` client / `vcp-store.conf` helper | Unchanged (+ WebAuthn knobs on helper) |
| TCB for release finalize / deletes | Peercred + Casbin in `vcp` only | **+ WebAuthn verified in `vcp-store`** (D10) |
| Release upload IPC | `put_begin` → write → `put_commit` | `put_begin` → write → **`put_prepare`** → ceremony → **`put_commit` + assertion** |
| Image upload | No step-up | Unchanged (no WebAuthn) |
| `delete` / `delete_org` | Peercred only | **WebAuthn required** (both scopes for `delete`) |
| Overwrite | Release atomic replace | **Release and image** atomic replace |
| Credential enrolment | — | Admin **CTAP2** dashboard + **CLI approve** on helper host |
| Credential revocation | — | **Dashboard only** (no helper CLI) |

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
| **D10** | **For sensitive mutations, `vcp` is untrusted:** WebAuthn assertions are **verified inside `vcp-store`** before materializing release packages or performing deletes | Peercred only proves UID 800; a compromised portal can already speak IPC |
| **D11** | Ceremony channel **C1**: browser ↔ `vcp` ↔ helper IPC (no separate auth HTTPS service in MVP) | Binding to helper-computed digest + one-shot challenges limits automated abuse; live MITM of admin UI remains a residual risk of C1 |
| **D12** | Admin product surface **CTAP2** (sidebar under Orgs): enrolment UX in portal; **activation only via CLI on the `vcp-store` host**; **revocation via dashboard without helper CLI** | Enrolment must not let compromised `vcp` inject ACTIVE keys; revocation DoS by compromised `vcp` is accepted |

---

## 2. Architecture

```text
                 ┌─────────────────────────────────────────────┐
                 │  vcp (UID 800)                              │
                 │  HTTPS · Casbin · sessions · ACME · DB      │
                 │  Postgres mirror + CTAP2 pending UX         │
                 │  WebAuthn ceremony relay (C1) only          │
                 └────────┼────────────────────────────────────┘
                          │  SOCK_SEQPACKET + SCM_RIGHTS
                          │  + WebAuthn assertion on gated ops
                 ┌────────▼────────────────────────────────────┐
                 │  vcp-store (UID 801 / vcp-storage)          │
                 │  digests SoT (meta.sqlite)                  │
                 │  WebAuthn RP verify + challenge store       │
                 │  Capsicum (FreeBSD) / soft fence            │
                 └────────┬────────────────────────────────────┘
                          │ openat(dirfd) only
                 ┌────────▼────────────────────────────────────┐
                 │  blob_path/  (vcp-storage:vcp-storage, 0700)│
                 │    meta.sqlite   # objects + webauthn_*     │
                 │    releases/<release_id>.pkg                │
                 │    images/<org_id>/<image_id>.<ext>         │
                 │    tmp/<upload_id>.partial                  │
                 └─────────────────────────────────────────────┘
```

CLI on the helper host (enrolment approve only):

```text
operator@helper  →  vcp-store ctap2 approve …  →  ACTIVE credential in SQLite
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
webauthn_rp_id = "access.vauban.sh"
webauthn_origin = "https://access.vauban.sh"
webauthn_challenge_ttl_secs = 300
```

### 3.3 Development / testing

| Env | IPC | `webauthn_required` |
|-----|-----|---------------------|
| development (`spawn`) | spawn | **true** (functional validation) |
| testing (`inline`) | inline | **false** (CI bypass) |
| production | socket | **true** |

Dev portal TOML still carries `blob_path` + quotas for spawn; helper WebAuthn
settings may live in a local helper conf or defaults passed on the spawn CLI.

---

## 4. Helper lifecycle and boot

Unchanged from 1.0 in spirit, with additions:

1. `umask(077)`; open `blob_path` dirfd; mkdir `releases/`, `images/`, `tmp/`.
2. Open/migrate **`meta.sqlite`** (objects + **webauthn_credentials** +
   **webauthn_challenges**) **before** `cap_enter`.
3. Load WebAuthn RP config from `vcp-store.conf`.
4. Bind listen socket; Capsicum / WARN; accept + `expected_peer_uid` (800).

`vcp-store ctap2 …` subcommands used for enrolment approve run as a **separate
invocation** (or privileged path) that can write SQLite before/without serving
IPC; they are not available over the portal Unix socket as an unauthenticated
enrolment finalize.

---

## 5. Storage layout and digests

Layout and digest SoT rules are as in 1.0:

- SoT: `meta.sqlite` → `objects` (`scope`, `object_key`, `org_id`, `sha256`,
  `size_bytes`, …).
- Mirror: Postgres `storage_objects` (portal only).
- **Overwrite:** a successful commit for an existing `releases/<id>.pkg` **or**
  `images/<org_id>/<image_id>.<ext>` is an atomic `renameat` replace + SQLite
  upsert (and then Postgres mirror upsert by `vcp`). Intended re-upload path
  for both families.

Image `object_key` form matches the portal mirror:
`{org_id}/{image_id}.{ext}`.

Additional SQLite tables (helper SoT for CTAP2):

```text
webauthn_credentials
  credential_id   BLOB PRIMARY KEY
  public_key_cose BLOB NOT NULL
  user_handle     TEXT NOT NULL        -- admin stable id / label binding
  admin_label     TEXT NOT NULL
  sign_count      INTEGER NOT NULL
  created_at      INTEGER NOT NULL
  revoked_at      INTEGER NULL         -- non-NULL => rejected on verify

webauthn_challenges
  challenge_id    TEXT PRIMARY KEY     -- base64url random
  op              TEXT NOT NULL        -- release_put_commit | delete | delete_org
  binding_json    TEXT NOT NULL        -- release_id / upload_id / digest / …
  expires_at      INTEGER NOT NULL
  consumed_at     INTEGER NULL
```

---

## 6. WebAuthn / CTAP2 (D10–D12)

### 6.1 When the helper requires WebAuthn

| Operation | Release | Image |
|-----------|---------|-------|
| `put_begin` / FD write | no | no |
| `put_prepare` + `put_commit` + assertion | **yes** | — (image uses monolithic commit, **no** WebAuthn) |
| Overwrite via successful commit | **yes** (release path) | no WebAuthn (image path) |
| `delete` | **yes** | **yes** |
| `delete_org` | — | **yes** |
| `get` / `stat` | no | no |

### 6.2 Gated release upload (variant Q + digest binding)

```text
put_begin → write FD → put_prepare → (C1 ceremony) → put_commit+assertion
```

1. **`put_begin` / write** — unchanged data plane; no WebAuthn.
2. **`put_prepare`** (release only) — helper, from its dup FD: `fstat`, full
   SHA-256, compare to client `sha256` expected (`digest_mismatch` if mismatch);
   **do not** `renameat`; store pending digest under `upload_id`; emit
   one-shot `challenge` bound to
   `{op=release_put_commit, release_id, upload_id, digest, exp}`; return
   `{digest, challenge, rp_id, allowCredentials}`.
3. **Ceremony (C1)** — `vcp` returns options to the admin browser;
   `navigator.credentials.get`; `vcp` relays assertion on commit.
4. **`put_commit`** — helper verifies assertion (COSE) against **ACTIVE**
   credentials, checks challenge map (unconsumed, unexpired, binding match
   including **helper digest**), consumes challenge, then `fsync` +
   `renameat` (overwrite OK) + SQLite `objects` upsert; returns size/sha256.
   `vcp` upserts Postgres mirror afterward.

Without a valid assertion: **no rename**, partial remains until TTL purge.

### 6.3 Deletes

```text
challenge_begin(op=delete|delete_org, …) → ceremony → delete*|delete_org + assertion
```

Challenge binding examples:

- `delete` release: `{op, scope=release, release_id}`
- `delete` image: `{op, scope=image, org_id, image_id, ext}`
- `delete_org`: `{op=delete_org, org_id}`

No content digest (object may already be gone from a race); binding is
identity + op + TTL + one-shot.

### 6.4 CTAP2 admin dashboard (portal)

- Sidebar Admin entry **CTAP2**, directly under **Orgs**.
- Casbin capability required (new permission, e.g. `ctap2` / `manage`);
  non-staff → **404** like other `/admin/*` entry points.
- **Per-admin keys** (model B): each enrolled credential is labeled to an
  admin identity (`user_handle` / label).

#### Enrolment (two-phase)

| Phase | Where | Effect |
|-------|-------|--------|
| E1 Web | `/admin/ctap2` | `credentials.create`; store **PENDING** enrolment artifact in portal DB (mirror/UX only); show fingerprint + CLI instructions |
| E2 CLI | Helper host | `vcp-store ctap2 approve …` writes **ACTIVE** row into helper SQLite. **Only** E2 makes a key usable for verify |

Compromised `vcp` must not be able to complete E2.

#### Revocation

- Performed **from the CTAP2 dashboard** (and matching IPC, e.g.
  `ctap2_revoke`), **without** helper-host CLI.
- Helper sets `revoked_at`; subsequent verifies fail.
- Threat acceptance: compromised `vcp` may revoke ACTIVE keys (ops DoS /
  lock-out) but cannot enrol new ACTIVE keys without CLI approve.

### 6.5 Error codes (closed set additions)

`webauthn_required`, `webauthn_invalid`, `webauthn_expired`,
`challenge_unknown`, plus existing
`not_found`, `invalid_id`, `quota`, `org_quota`, `bad_image`,
`digest_mismatch`, `integrity_mismatch`, `io`, `busy`.

---

## 7. IPC protocol

### 7.1 Control plane table

| Request | Response | FD | WebAuthn |
|---------|----------|----|----------|
| `get` + `sha256` | ok size/sha256 or `integrity_mismatch` | read | no |
| `stat` + `sha256` | ok size/sha256 or `integrity_mismatch` | — | no |
| `put_begin` | ok `upload_id` | write | no |
| `put_prepare` (release) | ok `digest`, `challenge`, … | — | emits challenge |
| `put_commit` (release) + assertion | ok size/sha256 | — | **verify** |
| `put_commit` (image) | ok size/sha256 | — | no |
| `put_abort` | ok | — | invalidates related challenge if any |
| `challenge_begin` (delete*) | ok `challenge`, … | — | emits challenge |
| `delete` + assertion | ok | — | **verify** |
| `delete_org` + assertion | ok `deleted` | — | **verify** |
| `ctap2_revoke` | ok | — | no (dashboard-driven; marks revoked) |

Message size still under 4 KiB for control JSON; large attestation blobs for
enrolment E1 stay in portal pending storage, not necessarily on the SEQPACKET
hot path.

### 7.2 Data plane

**Download / verify-on-read** — unchanged from 1.0 (mirror sha → SQLite →
re-hash → FD).

**Image upload** — `put_begin` → write → `put_commit` (sniff + rename +
SQLite); overwrite allowed; no WebAuthn.

**Release upload** — §6.2 gated path with `put_prepare`.

---

## 8. Capsicum and portable hardening

As in 1.0, plus:

- WebAuthn verify is CPU + already-open SQLite (no outbound network from
  helper).
- Credential and challenge tables live under `blob_path` with blobs.
- `ctap2 approve` CLI is an offline/admin path on the helper host, not an
  ambient capability of the sandboxed accept loop.

---

## 9. Threat model (digest + WebAuthn)

| Threat | Mitigation |
|--------|------------|
| Forged Postgres mirror digest | verify-on-read / `integrity_mismatch` |
| Tampered blob on disk | re-hash vs SQLite |
| Compromised `vcp` opens `blob_path` | UID 801 + 0700 |
| Compromised `vcp` calls IPC without human | WebAuthn on release finalize + deletes |
| Compromised `vcp` swaps package after ceremony | Challenge bound to **helper digest** from `put_prepare` |
| Compromised `vcp` enrols attacker key | E2 CLI approve required |
| Compromised `vcp` revokes keys | Accepted residual (dashboard revocation) |
| Live MITM of admin ceremony (C1) | Residual of C1; harden later with C2 if needed |

Casbin remains necessary for UX and tenant IDOR; it is **not** sufficient for
D10 mutations once `vcp` is compromised.

---

## 10. Tests (1.1 additions)

Pyramid layers must cover:

- Unit: challenge TTL/consume; assertion binding mismatch; revoked cred
  rejected; image commit without WebAuthn; release commit without assertion
  denied when `webauthn_required`.
- Invariants: CTAP2 route under admin; `put_prepare` in protocol; doc 1.1
  pins; `webauthn_required` false in testing config path.
- Battle: concurrent prepare/commit; revoke vs in-flight challenge.
- E2E (dev-like): release upload with WebAuthn test authenticator; delete
  gated; image upload without WebAuthn; overwrite release + image.
- Enrolment: pending in portal does not satisfy helper verify until CLI
  approve (manual/runbook + automated fake approve in test harness).
- Testing env: bypass flag allows existing storage_* suites without
  authenticators.

---

## 11. Implementation plan (1.1)

| Phase | Content |
|-------|---------|
| A | Doc 1.1 + conf knobs + error codes + protocol types (`put_prepare`, assertion fields) |
| B | SQLite `webauthn_*` + verify crate wiring inside helper; testing bypass |
| C | Release upload path: prepare/commit + Admin UX ceremony (C1) |
| D | `delete` / `delete_org` challenge + assertion |
| E | Admin **CTAP2** dashboard (pending enrol + revoke); CLI `vcp-store ctap2 approve` |
| F | Runbooks + smoke: enrolment approve, revoke, release sign, delete sign |

Phases A–F each ship with the behavioral test pyramid on touched seams.

---

## 12. Bottom line

1.0 delivered a Capsicum-ready helper, SQLite digest SoT, Postgres mirror, and
verify-on-read. **1.1 raises the TCB for release publication and all deletes:**
`vcp-store` is the WebAuthn Relying Party; humans prove presence with
**per-admin CTAP2 credentials** activated only by **CLI on the helper host**,
while the Admin **CTAP2** UI handles enrolment pending state and **revocation
without CLI**. Image uploads stay fast and ungated by WebAuthn; overwrites
remain atomic for both families. Development exercises WebAuthn;
automated testing bypasses it.
