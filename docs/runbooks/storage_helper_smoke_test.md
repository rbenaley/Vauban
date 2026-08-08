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
| **Fail** | No release row is created, download **404**/**503**, or digest mismatch. |

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

Follow-on (issue gallery): after upload, attach the token to a new issue
and confirm the detail gallery — see
[`portal_issues_smoke_test.md`](portal_issues_smoke_test.md) § F.

## C -- Helper down / recovery (Pass / Fail)

1. Stop `vcp-store` (socket mode) while `vcp` keeps running.
2. Portal **Download** button (`POST /{org}/builds/{ver}/download`) → **303**
   back to `/{org}/builds/{ver}?…&dl_error=unavailable`, and the page raises
   the **Download unavailable** modal (never a plain-text page). Image upload
   on artifact routes → **503** (upload unavailable) — not a silent 200.
3. Machine surface unchanged: `curl -i https://…/releases/{token}/{pkg}` →
   **503** with body `download unavailable`.
4. Restart helper; retry → success without restarting portal (or after
   one reconnect if the client held a dead FD).

| Result | Criteria |
|--------|----------|
| **Pass** | Portal modal on Builds, 503 text for cURL, then recovery. |
| **Fail** | Portal panic, plain-text error page in the browser, hung request with no status, or silent 200 while helper is down. |

## D -- Integrity mismatch (Pass / Fail)

1. With a published release (or org image) that has a mirror row, temporarily
   forge Postgres `storage_objects.sha256` to a different 64-hex value (or
   restore a backup where mirror ≠ SQLite).
2. Attempt the portal download as an entitled user → **303** to
   `?dl_error=integrity` and the **Signature check failed** modal. Image GET
   and `curl /releases/{token}/{pkg}` → **503** (`integrity mismatch`).
   Helper must **not** issue an FD (`integrity_mismatch`).
3. Restore the correct mirror digest (or re-upload); retry → **200**.

Optional: with matching mirror + SQLite, corrupt the on-disk blob bytes under
the known key → same deny on verify-on-read.

| Result | Criteria |
|--------|----------|
| **Pass** | Forged mirror or tampered blob → modal (portal) / 503 (cURL); fix → serve again. |
| **Fail** | Bytes served despite digest drift, or chatty path leak. |

## E -- Production guards (Pass / Fail)

1. Confirm `vcp.conf` has `ipc = "socket"` + `socket_path`, and
   `vcp-store.conf` has absolute `blob_path` + `listen`.
2. Confirm blob root not writable by portal UID (`touch` as `vcp` fails).
3. Confirm socket peercred rejects a foreign UID (optional: connect as
   another user → helper logs reject / drops).
4. On FreeBSD: helper log shows `cap_enter` success **or** documented soft
   path; see Capsicum checklist in [`storage_helper_ops.md`](storage_helper_ops.md).
5. On FreeBSD after `cap_enter`: admin issue reply with screenshot **and**
   release package upload must succeed (SCM_RIGHTS via dirfd reopen — not
   absolute `File::open`). Expect **no**
   `Not permitted in capability mode` on happy-path `put_begin` / `get`.

| Result | Criteria |
|--------|----------|
| **Pass** | Socket mode, helper conf owns blob root, peercred enforced; Capsicum hosts serve uploads/downloads. |
| **Fail** | Portal accepts `ipc=spawn` in production, shared writable storage, or Capsicum `ENOTCAPABLE` on image/release handoff. |

## F -- WebAuthn C1 release publish (Pass / Fail)

Requires at least one ACTIVE KEY key (see ops breakglass / KEY enrol).

1. Admin → Publish release with package. Confirm redirect to
   `/admin/releases/confirm?token=…` showing **helper** summary
   (`release_put_commit id=… sha256=…`) with the **full 64-hex** digest
   visible (wrapped if needed, never elided).
2. On helper host: `vcp-store pending-ops` shows the same canonical `summary`
   in the in-flight challenges table; the digests must match character for
   character.
3. Complete WebAuthn (UV required). Release becomes PUBLISHED; download
   matches digest.
4. Negative — **Cancel publish** on the confirm page: no rename, and
   `/admin/releases` shows **no** row for that version (the staged row is
   deleted, not left unpublished).
5. Negative — walk away instead (close the tab, refuse UV). The version must
   never appear on `/admin/releases`; after the ceremony TTL (300 s) the next
   Release manager visit drops the staged row and frees the upload slot.
   Restarting the portal mid-ceremony has the same effect on the next visit.

| Result | Criteria |
|--------|----------|
| **Pass** | Summary is helper-issued with the full digest; publish only after valid assertion; an abandoned ceremony leaves no release row and no committed blob. |
| **Fail** | Publish without ceremony, UI invents its own summary label, the digest is truncated / clipped out of the panel, or a cancelled publish leaves a row on `/admin/releases`. |

## G -- KEY enrol / approve / revoke (Pass / Fail)

Local lab: open **`https://localhost:3000/admin/key`** (not `127.0.0.1`).
WebAuthn rejects IP hosts; `webauthn_origin` uses `localhost` (RP ID derived).
Accept the self-signed cert for `localhost` if prompted.

Production / EC2 lab: set the **same** `webauthn_origin` in both
`/usr/local/etc/vcp/vcp.conf` (`[storage]`) and `vcp-store.conf`, matching
the browser URL hostname. `/admin/key` reads the **portal** value; the helper
file alone is not enough. After changing origin, restart `vcp` and `vcp_store`.

1. `/admin/key` → Create key → PENDING fingerprint shown; activate from the
   helper host (`vcp-store approve-key`, copy from PENDING table if needed).
   PENDING and ACTIVE tables paginate at **4** rows (`pending_page` /
   `active_page`); confirm Next when more than four keys exist.
2. **Empty / whitespace-only key label** (leave label blank or spaces, click
   Create): must **not** open the authenticator dialog; banner / redirect
   `err=label`. No PENDING row in `vcp-store pending-ops`.
3. **PENDING TTL** (`webauthn_pending_ttl_hours`, default 24): an unapproved
   PENDING older than the TTL must show as `expired` in `list-keys` and
   leave the `pending-ops` queue; `approve-key` for that fingerprint
   fails closed (`webauthn_expired`).
4. Activate (E2) with OOB fingerprint match:
   `vcp-store approve-key --fingerprint <hex>` (pass `--blob-path` or
   `--config` when not using the default `vcp-store.conf`).
5. Cross-check listing:
   - `vcp-store pending-ops` shows the pending credential (not only challenges).
   - After approve: `vcp-store list-keys` shows ACTIVE; pending queue empty.
6. Dashboard lists ACTIVE; revoke from dashboard (no CLI revoke).
7. Wrong fingerprint on approve → fail closed; no ACTIVE insert.

| Result | Criteria |
|--------|----------|
| **Pass** | Blank label fails closed; stale PENDING becomes `expired`; pending/list reflect E2 queue; only CLI approve activates; revoke is dashboard-only (ADR 003). |
| **Fail** | Empty label reaches `credentials.create`, stale PENDING stays approvable, pending omits staged keys, portal-only activate, or approve without fingerprint match. |

## H -- Storage denial logging (Pass / Fail)

When an artifact / issue-image upload fails for a **real** denial (helper
down, quota, bad image), operators must see **WARN/ERROR** lines — not a
silent UI redirect. Happy-path Capsicum uploads must **not** emit
`ENOTCAPABLE` (dirfd handoff).

1. Set `RUST_LOG=vcp=debug,vcp-store=debug` (or at least `warn`) on both
   portal and helper consoles.
2. Force a known denial (stop the helper mid-flight, or exceed image quota).
3. Expect helper / portal WARN lines with closed `code=` / `surface=`.
4. Negative (regression): under Capsicum, a normal screenshot upload must
   **not** log `Not permitted in capability mode` on `put_begin`.

| Result | Criteria |
|--------|----------|
| **Pass** | Intentional denial produces WARN; Capsicum happy path is quiet + succeeds. |
| **Fail** | UI fails with empty console, or Capsicum happy path still logs ENOTCAPABLE. |

## Related automated coverage

| Layer | Filter / artifact |
|-------|-------------------|
| Invariants | `storage_invariants_`, `scripts/check_storage.sh` (dirfd handoff pins) |
| Proptest | `storage_proptest` (handoff rel paths), `storage::log` proptest |
| Battle | `battle_concurrent_dirfd_handoff_write_commit`, `storage::log` battle |
| E2E | `storage_e2e_`, `e2e_spawn_ipc_image_put_get_scm_rights` |
| Smoke | This runbook §E/§H (Capsicum happy path + denial logging) |
