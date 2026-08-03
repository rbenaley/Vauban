# Runbook -- Storage helper (`vcp-store`) operations

> Operator guide for the sandboxed artifact helper: restart, blob root
> rotation, digest mismatch, org image purge, Capsicum / FreeBSD jail
> checklist, and production socket ownership.
>
> Audience: staging / production operators.
> Severity: **BLOCKING** for artifact upload/download incidents.
>
> Design: [VCP_Storage_Helper_Architecture_EN(1.0).md](../technical/VCP_Storage_Helper_Architecture_EN(1.0).md)
> Smoke: [`storage_helper_smoke_test.md`](storage_helper_smoke_test.md)
> Audit: [`.cursor/audits/vcp_capsicum_storage_sandbox_2026-08-02.md`](../../.cursor/audits/vcp_capsicum_storage_sandbox_2026-08-02.md)

## Automated prerequisites

```bash
bash scripts/check_storage.sh
rtk cargo test --test integration_tests -- storage_ -- --test-threads=1
rtk cargo test -p vcp --lib production_rejects_storage_ipc_spawn -- --test-threads=1
```

## Production layout (socket mode)

| Item | Typical path / mode |
|------|---------------------|
| Config | `/usr/local/etc/vcp/vcp.conf` (`storage.ipc = "socket"`) |
| Blob root | `/var/db/vcp/storage` owned by `vcp-store:vcp-store`, mode **0700** |
| Listen socket | `/var/run/vcp/store.sock` — directory **0700**, socket owned so only `vcp` UID can connect |
| Helper binary | `/usr/local/sbin/vcp-store` (or `storage.helper_path`) |
| Portal UID | `vcp` — **must not** write `blob_path` (boot refuses writable root) |

`vcp` talks to the helper over the named SEQPACKET socket. The helper
checks **peer credentials** (`getpeereid` / `SO_PEERCRED`) when
`expected_peer_uid` / `--expected-uid` is set and rejects foreign UIDs.

### rc.d / service ownership

1. Start **`vcp-store` before `vcp`** (or restart both if the socket vanished).
2. Ensure the socket directory is created as root / service user with mode
   **0700** before bind (helper also `create_dir_all` on the parent).
3. After bind, confirm:
   - `ls -ld /var/run/vcp` → `drwx------` for the store / runtime user;
   - `ls -l /var/run/vcp/store.sock` → socket; only portal UID can connect;
   - `ls -ld /var/db/vcp/storage` → `drwx------ vcp-store vcp-store`.
4. Portal boot with `ipc=spawn` or a blob root writable by the `vcp` UID
   **fails validation** — fix ownership before restarting `vcp`.

Example FreeBSD `rc.conf` sketch (adjust names to your package):

```sh
vcp_store_enable="YES"
vcp_enable="YES"
# vcp_store_user="vcp-store"
# vcp_store_flags="--blob-path /var/db/vcp/storage --listen /var/run/vcp/store.sock --production --expected-uid <vcp-uid>"
```

## Restart helper

1. Stop portal traffic if needed (or accept brief **503** on artifact routes).
2. `service vcp-store restart` (or kill + rc start). Confirm listen log:
   `vcp-store listening`.
3. Restart / leave `vcp` running — reconnects on next request (socket mode).
4. Smoke: admin upload a tiny package **or** run
   [`storage_helper_smoke_test.md`](storage_helper_smoke_test.md) section A.

Pass: helper listens; peercred accepts `vcp`; artifact GET returns 200.

## Rotate `blob_path`

1. Provision new directory as `vcp-store:vcp-store` **0700**.
2. Stop helper; rsync/move `releases/`, `images/`, `tmp/` (drop stale `tmp/*.partial`).
3. Point `storage.blob_path` in `vcp.conf` at the new root; keep `ipc=socket`.
4. Start helper; confirm portal UID still cannot write the new root.
5. Restart `vcp` so config reload validates the new path.
6. Smoke download of a known release + one org image.

Fail: portal boots with writable blob root, or digests 404 after move
(incomplete copy).

## Digest mismatch

Symptoms: admin upload stays **HIDDEN**, or helper returns `digest_mismatch`
during `put_commit`; client sees **400** on image commit.

1. Confirm client hashed the same FD bytes the helper hashed (no truncated body).
2. Re-upload; do not hand-edit `storage_objects.sha256`.
3. If DB row drifted from disk, delete the catalog release / image row and
   re-upload (helper is SoT for bytes; Postgres is SoT for published digests).

## `delete_org` (tenant offboarding)

When an organization is deleted, `vcp` calls helper `delete_org` and removes
matching `storage_objects` image rows. Operators:

1. Confirm companies delete path completed without **503**.
2. Check disk: `images/<org_id>/` gone under `blob_path`.
3. SQL: no `storage_objects` rows with that `organization_id` (scope `image`).

## Capsicum / FreeBSD checklist (manual)

CI on macOS/Linux keeps the soft-containment WARN path. On FreeBSD hosts:

- [ ] Helper runs as dedicated `vcp-store` UID (not shared with `vcp`).
- [ ] Boot logs `Capsicum: entered capability mode via cap_enter` (or
      documented soft path if API unavailable in the jail).
- [ ] Optional: run helper inside a thin jail / **gisco**-style containment
      with only the blob mount + socket path visible — validate upload and
      download still succeed; confirm helper cannot open paths outside the
      jail root.
- [ ] After `cap_enter`, helper must not need fresh global `open` of the
      blob tree (dirfd already held).
- [ ] Portal process itself is **not** under Capsicum (by design).

Do **not** expect macOS CI to exercise `cap_enter` or jail.

## Related smoke surfaces

| Surface | Runbook |
|---------|---------|
| Builds download / ephemeral | [`builds_entitlement_smoke_test.md`](builds_entitlement_smoke_test.md) |
| Admin release upload | [`admin_releases_smoke_test.md`](admin_releases_smoke_test.md) |
| Storage helper focused | [`storage_helper_smoke_test.md`](storage_helper_smoke_test.md) |

## Related automated coverage

| Layer | Filter / artifact |
|-------|-------------------|
| Invariants | `storage_invariants_`, `scripts/check_storage.sh` |
| Proptest | `storage_proptest` |
| Battle | `storage_battle_` |
| E2E | `storage_e2e_` |
| Config | `production_rejects_storage_ipc_spawn`, `production_rejects_writable_blob_path` |
