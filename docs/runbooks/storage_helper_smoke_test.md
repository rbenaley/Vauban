# Runbook -- Storage helper smoke test

> Manual validation after shipping **vcp-store** (releases + org images via
> IPC; digest SoT = helper SQLite `meta.sqlite`; Postgres `storage_objects`
> = portal mirror; production socket + peercred). CI covers unit /
> invariants / proptest / battle / in-process E2E against `vcp_test`;
> staging proves helper process, socket ownership, and HTTPS artifact paths.
>
> Audience: staging / production operators.
> Severity: **BLOCKING** for artifact storage changes. Do not ship without A–E.

Related:

- Ops: [`storage_helper_ops.md`](storage_helper_ops.md)
- Architecture: [VCP_Storage_Helper_Architecture_EN(1.2).md](../technical/VCP_Storage_Helper_Architecture_EN(1.2).md)
- Lint: `scripts/check_storage.sh`
- Filter: `cargo test --test integration_tests -- storage_ -- --test-threads=1`
- Builds: [`builds_entitlement_smoke_test.md`](builds_entitlement_smoke_test.md)
- Admin releases: [`admin_releases_smoke_test.md`](admin_releases_smoke_test.md)

## Automated prerequisites

```bash
bash scripts/setup_test_db.sh   # or: just db-create-test
rtk cargo fmt --all -- --check
rtk cargo clippy -p vcp --all-targets -- -D warnings
bash scripts/check_storage.sh
rtk cargo test --test integration_tests -- storage_ -- --test-threads=1
```

## Lab prerequisites

- Staging: `storage.ipc = "socket"`, helper running as `vcp-storage` (801), blob root
  **0700**, socket parent **0700**, peercred expected UID = portal.
- Dev alternative: `VCP_ENVIRONMENT=development` + `just run` (`ipc=spawn`).
- Seed staff `support@vauban.sh` / client `l.martin@acme.example` on
  `acme-infrastructure`.
- Browser or `curl -k` for local HTTPS.

## A -- Release upload → download (Pass / Fail)

1. Sign in as `support@vauban.sh`.
2. `/admin/releases/new` — create a GA release with a small `.pkg` file.
3. Expect list STATUS **PUBLISHED** and SIGNATURE a full 64-hex digest
   (from the Postgres **mirror** / UI, not a stub). Helper SQLite SoT holds
   the same digest after `put_commit`.
4. Sign in as `l.martin@acme.example`; open `/acme-infrastructure/builds`.
5. **Download** the new version — HTTP **200**,
   `Content-Disposition` attachment, `X-Content-Type-Options: nosniff`.
6. Locally `sha256` the file; match the Builds SIGNATURE column.

| Result | Criteria |
|--------|----------|
| **Pass** | Upload publishes; download bytes hash matches UI digest. |
| **Fail** | Row stays HIDDEN, download **404**/**503**, or digest mismatch. |

## B -- Org image upload / serve (Pass / Fail)

1. As org member with issues access, `POST /{org}/images` multipart field
   `image` with a PNG/JPEG/WebP (Issues compose drop-zone is fine).
2. Expect **201** and body `\<uuid\>.\<ext\>`.
3. `GET /{org}/images/\<uuid\>.\<ext\>` → **200**, correct `Content-Type`,
   `X-Content-Type-Options: nosniff`.
4. As another org member, GET the same filename under their slug → **404**.
5. GET a random UUID `.png` with no Postgres mirror row → **404**
   (must not depend on helper `not_found` alone).

| Result | Criteria |
|--------|----------|
| **Pass** | Own-org 200 + nosniff; cross-tenant / missing mirror row 404. |
| **Fail** | Cross-org 200, missing nosniff, or 503 when mirror row is absent. |

## C -- Helper down / recovery (Pass / Fail)

1. Stop `vcp-store` (socket mode) while `vcp` keeps running.
2. Download or image upload on artifact routes → **503**
   (`download unavailable` / upload unavailable) — not a silent 200.
3. Restart helper; retry → success without restarting portal (or after
   one reconnect if the client held a dead FD).

| Result | Criteria |
|--------|----------|
| **Pass** | Degraded 503 then recovery. |
| **Fail** | Portal panic, hung request with no status, or silent 200 while helper is down. |

## D -- Integrity mismatch (Pass / Fail)

1. With a published release (or org image) that has a mirror row, temporarily
   forge Postgres `storage_objects.sha256` to a different 64-hex value (or
   restore a backup where mirror ≠ SQLite).
2. Attempt download / image GET as an entitled user → **503** (integrity /
   artifact unavailable). Helper must **not** issue an FD (`integrity_mismatch`).
3. Restore the correct mirror digest (or re-upload); retry → **200**.

Optional: with matching mirror + SQLite, corrupt the on-disk blob bytes under
the known key → same deny on verify-on-read.

| Result | Criteria |
|--------|----------|
| **Pass** | Forged mirror or tampered blob → 503 / deny; fix → serve again. |
| **Fail** | Bytes served despite digest drift, or chatty path leak. |

## E -- Production guards (Pass / Fail)

1. Confirm `vcp.conf` has `ipc = "socket"` + `socket_path`, and
   `vcp-store.conf` has absolute `blob_path` + `listen`.
2. Confirm blob root not writable by portal UID (`touch` as `vcp` fails).
3. Confirm socket peercred rejects a foreign UID (optional: connect as
   another user → helper logs reject / drops).
4. On FreeBSD: helper log shows `cap_enter` success **or** documented soft
   path; see Capsicum checklist in [`storage_helper_ops.md`](storage_helper_ops.md).

| Result | Criteria |
|--------|----------|
| **Pass** | Socket mode, helper conf owns blob root, peercred enforced. |
| **Fail** | Portal accepts `ipc=spawn` in production, or shared writable storage. |

## F -- WebAuthn C1 release publish (Pass / Fail)

Requires at least one ACTIVE KEY key (see ops breakglass / KEY enrol).

1. Admin → Publish release with package. Confirm redirect to
   `/admin/releases/confirm?token=…` showing **helper** summary
   (`release_put_commit id=… sha256=…`).
2. On helper host: `vcp-store key pending` shows the same summary/binding.
3. Complete WebAuthn (UV required). Release becomes PUBLISHED; download
   matches digest.
4. Negative: abort ceremony / refuse UV → release stays HIDDEN; no rename.

| Result | Criteria |
|--------|----------|
| **Pass** | Summary is helper-issued; publish only after valid assertion. |
| **Fail** | Publish without ceremony, or UI invents its own summary label. |

## G -- KEY enrol / approve / revoke (Pass / Fail)

Local lab: open **`https://localhost:3000/admin/key`** (not `127.0.0.1`).
WebAuthn rejects IP hosts; `webauthn_origin` uses `localhost` (RP ID derived).
Accept the self-signed cert for `localhost` if prompted.

1. `/admin/key` → Create passkey → PENDING fingerprint shown + CLI hint.
2. **Empty / whitespace-only key label** (leave label blank or spaces, click
   Create): must **not** open the authenticator dialog; banner / redirect
   `err=label`. No PENDING row in `vcp-store key pending`.
3. **PENDING TTL** (`webauthn_pending_ttl_hours`, default 24): an unapproved
   PENDING older than the TTL must show as `expired` in `key list` and
   leave the `key pending` queue; `key approve` for that fingerprint
   fails closed (`webauthn_expired`).
4. Activate (E2) with OOB fingerprint match:
   - **Local spawn (`just run`):** from the repo root,
     `VCP_ENVIRONMENT=development ./target/debug/vcp-store key approve --fingerprint <hex>`
     (loads the same `[storage].blob_path` as the portal, typically
     `<repo>/vcp-storage`). Bare `vcp-store` without the env var reads
     production `vcp-store.conf` (`/var/db/vcp/storage`) and fails on Mac.
   - **Production helper host:** `vcp-store key approve --fingerprint <hex>`
5. Cross-check listing:
   - `vcp-store key pending` shows the PENDING credential (not only challenges).
   - After approve: `vcp-store key list` shows ACTIVE; pending queue empty.
6. Dashboard lists ACTIVE; revoke from dashboard (no CLI revoke).
7. Wrong fingerprint on approve → fail closed; no ACTIVE insert.

| Result | Criteria |
|--------|----------|
| **Pass** | Blank label fails closed; stale PENDING becomes `expired`; pending/list reflect E2 queue; only CLI approve activates; revoke is dashboard-only (ADR 003). |
| **Fail** | Empty label reaches `credentials.create`, stale PENDING stays approvable, pending omits staged keys, portal-only activate, or approve without fingerprint match. |

## Related automated coverage

| Layer | Filter / artifact |
|-------|-------------------|
| Invariants | `storage_invariants_`, `scripts/check_storage.sh` |
| Proptest | `storage_proptest` |
| Battle | `storage_battle_` |
| E2E | `storage_e2e_` |
