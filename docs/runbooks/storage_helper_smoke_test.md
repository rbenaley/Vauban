# Runbook -- Storage helper smoke test

> Manual validation after shipping **vcp-store** (releases + org images via
> IPC, `storage_objects` digest SoT, production socket + peercred). CI covers
> unit / invariants / proptest / battle / in-process E2E against `vcp_test`;
> staging proves helper process, socket ownership, and HTTPS artifact paths.
>
> Audience: staging / production operators.
> Severity: **BLOCKING** for artifact storage changes. Do not ship without A–D.

Related:

- Ops: [`storage_helper_ops.md`](storage_helper_ops.md)
- Architecture: [VCP_Storage_Helper_Architecture_EN(1.0).md](../technical/VCP_Storage_Helper_Architecture_EN(1.0).md)
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

- Staging: `storage.ipc = "socket"`, helper running as `vcp-store`, blob root
  **0700**, socket parent **0700**, peercred expected UID = portal.
- Dev alternative: `VCP_ENVIRONMENT=development` + `just run` (`ipc=spawn`).
- Seed staff `support@vauban.sh` / client `l.martin@acme.example` on
  `acme-infrastructure`.
- Browser or `curl -k` for local HTTPS.

## A -- Release upload → download (Pass / Fail)

1. Sign in as `support@vauban.sh`.
2. `/admin/releases/new` — create a GA release with a small `.pkg` file.
3. Expect list STATUS **PUBLISHED** and SIGNATURE a full 64-hex digest
   (from `storage_objects`, not a stub).
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
5. GET a random UUID `.png` with no `storage_objects` row → **404**
   (must not depend on helper `not_found` alone).

| Result | Criteria |
|--------|----------|
| **Pass** | Own-org 200 + nosniff; cross-tenant / missing row 404. |
| **Fail** | Cross-org 200, missing nosniff, or 503 when row is absent. |

## C -- Helper down / recovery (Pass / Fail)

1. Stop `vcp-store` (socket mode) while `vcp` keeps running.
2. Download or image upload on artifact routes → **503**
   (`download unavailable` / upload unavailable) — not a silent 200.
3. Restart helper; retry → success without restarting portal (or after
   one reconnect if the client held a dead FD).

| Result | Criteria |
|--------|----------|
| **Pass** | Degraded 503 then recovery. |
| **Fail** | Portal panic, 501 stub, or hung request with no status. |

## D -- Production guards (Pass / Fail)

1. Confirm `vcp.conf` has `ipc = "socket"` and absolute `blob_path`.
2. Confirm blob root not writable by portal UID (`touch` as `vcp` fails).
3. Confirm socket peercred rejects a foreign UID (optional: connect as
   another user → helper logs reject / drops).
4. On FreeBSD: helper log shows `cap_enter` success **or** documented soft
   path; see Capsicum checklist in [`storage_helper_ops.md`](storage_helper_ops.md).

| Result | Criteria |
|--------|----------|
| **Pass** | Socket mode, non-writable blob root, peercred enforced. |
| **Fail** | Portal accepts `ipc=spawn` in production, or shared writable storage. |

## Related automated coverage

| Layer | Filter / artifact |
|-------|-------------------|
| Invariants | `storage_invariants_`, `scripts/check_storage.sh` |
| Proptest | `storage_proptest` |
| Battle | `storage_battle_` |
| E2E | `storage_e2e_` |
