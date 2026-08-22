# Runbook -- Admin release manager

> Manual validation after shipping **release STATUS/ACTIONS** (PUBLISHED /
> HIDDEN badges, Edit / Publish|Unpublish / Delete). CI covers unit /
> invariants / proptest / battle / in-process E2E against `vcp_test`;
> staging proves browser HTTPS and denial paths.
>
> Audience: release / staging operators.
> Severity: **BLOCKING** for this surface. Do not ship without A–B.

Related:

- [README](../../README.md) (seed login, route map)
- Lint: `scripts/check_admin_releases.sh`
- Storage helper: [`storage_helper_smoke_test.md`](storage_helper_smoke_test.md)
- Pyramid: `.cursor/rules/vcp-test-pyramid.mdc`
- Filter: `cargo test --test integration_tests -- admin_releases -- --test-threads=1`
- Auth denials: [`auth_tenant_smoke_test.md`](auth_tenant_smoke_test.md)

## Automated prerequisites

```bash
bash scripts/setup_test_db.sh   # or: just db-create-test
rtk cargo fmt --all -- --check
rtk cargo clippy --all-targets -- -D warnings
bash scripts/check_admin_releases.sh
rtk cargo test --test integration_tests -- admin_releases -- --test-threads=1
rtk cargo test --test integration_tests -- builds_entitlement_ -- --test-threads=1
```

## Lab prerequisites

- `VCP_ENVIRONMENT=development` + `just run` (HTTPS `https://127.0.0.1:3000`).
- Browser or `curl -k` willing to accept the local self-signed cert.
- Seed users: staff `support@vauban.sh` / `password`; client
  `l.martin@acme.example` / `password` on `acme-infrastructure`.

## A -- Happy path

1. Sign in as `support@vauban.sh` / `password`.
2. Open `/admin/releases/new` and publish a GA release (empty target org)
   **with a real FreeBSD `.pkg`** so `vcp-store` commits the blob and
   `storage_objects` is upserted. There are no Version / Channel fields —
   both are read from the package manifeste (`Version` ending in `+LTS`
   → LTS, otherwise Stable). **Date is mandatory** (no Unix-epoch
   default): omit it and Publish is refused with a compose banner, and
   nothing is created. The package is mandatory: submitting without one
   is refused and creates nothing. A random binary / non-pkg upload
   raises the Concept confirm modal (**Not a FreeBSD package**) **without
   wiping Date / Org / Notes** (Topcoat `$()` calls `require_active_key`,
   then `@animationend` / `vb-pkg-kick` POSTs `validate-pkg` — in-process
   tests never click Publish in a browser; a one-shot
   `animationiteration` is a silent client no-op); re-pick a real
   `.pkg` and Publish again. Creates nothing until a valid package is
   accepted. With WebAuthn required and **no ACTIVE key** in vcp-store,
   Publish opens the **No active security key** signal modal and must
   **not** start a passkey prompt.
3. With WebAuthn enabled, confirm `/admin/releases/confirm` shows the
   parsed package summary (`Name`, `Version`, `Origin`, `Architecture`,
   …) **before** you sign — then complete the ceremony.
4. On `/admin/releases`, confirm STATUS shows a green **PUBLISHED** badge,
   SIZE reflects the stored blob, VERSION omits a trailing `+LTS` (channel
   badge carries LTS), and ACTIONS has **Edit** / **Unpublish** / Delete
   (trash).
5. Publish an org-targeted hotfix; confirm TARGET column on the list.
6. Click **Unpublish** — STATUS becomes amber **HIDDEN**. Confirm the version is
   absent under `/{org}/builds`, `/vauban/builds`, and the dashboard latest-build
   card on `/vauban` (and `/{org}`). Manage HIDDEN rows only on `/admin/releases`.
   List order is SQL semver, then `status DESC` (PUBLISHED before HIDDEN when the
   version keys match). Unpublishing must not reorder rows with **different**
   versions; when a second row shares the same version (e.g. republish `1.0.1`),
   the HIDDEN twin must sit **below** the PUBLISHED one.
7. Click **Publish** — builds + dashboard show the version again.
8. Open **Edit** (`/admin/releases/{id}`): only Channel (LTS+EOL or
   Stable+EOL), Target organization, and Release notes. Flip channel /
   org / notes, Save — list reflects the update. Version and date stay
   fixed from publish.
9. Delete via trash → type `delete` → **Delete permanently**; row is gone.
10. Interrupted publish (WebAuthn enabled): start a publish, then hit **Cancel
   publish** on `/admin/releases/confirm` — the list must show **no** row for
   that version. Repeat by closing the tab instead: still no row, and the
   staged upload is dropped on a later Release manager visit.

Pass: surface behaves as in the focused E2E suite; an unfinished publish
leaves no trace.

## B -- Denial paths

1. As `l.martin@acme.example`, confirm `/admin/releases` returns **404**.
2. Member POSTs to `/admin/releases/{id}/publish|unpublish|delete` → **404**.
3. While authenticated, open a non-member org slug — expect **404**.
4. Anonymous / expired session must not leak tenant data.
5. As staff, on `/admin/releases/new` fill Date / notes, attach a random
   file, Publish — expect the **Not a FreeBSD package** modal, Date / Org /
   Notes still filled, no new row. Re-pick a real `.pkg` and succeed.
   (Without the Topcoat runtime, the PRG `?err=not_pkg` fallback still
   shows the modal but fields are cleared.)
6. With WebAuthn required and **no ACTIVE key** in vcp-store (revoke all
   keys / fresh helper DB), Publish — expect the **No active security key**
   modal (same Concept chrome as not_pkg). WebAuthn must **not** open.
   Enrol + `vcp-store approve-key`, then Publish again.

Pass: Casbin + tenant + FreeBSD package + ACTIVE-key gates fail-closed.

## C -- Channel chips + pagination

SSR list paging (10 rows per page) with Builds-style channel chips.

1. On `/admin/releases`, expect chips **[All][LTS][Stable][EOL]** on the left
   and (when 11+ rows) a pager on the right of the same chip row.
2. Click **Stable** — only Stable rows remain; chip hrefs must **not** carry
   `?page=` (filter resets to page 1). Column gutters must match page 1 / page 2
   (CSS grid tracks — no column jump between pages) and match the inter-column
   spacing on `/{org}/builds` (`--vb-catalog-gap`).
3. With **11+** Stable releases, open `?channel=Stable&page=2` — remainder only,
   pager keeps `channel=Stable`.
4. Pager links must **not** sticky-carry `?delete=` / `err=`.

Pass: chips filter SQL-side; 10 max per page; Builds-matching column gutters.

## Related automated coverage

| Layer | Filter / artifact |
|-------|-------------------|
| Invariants | `inv_`, `scripts/check_admin_releases.sh` |
| Proptest | `prop_` |
| Battle | `battle_` |
| E2E | `e2e_` (`--test integration_tests`) |
| Builds visibility | `builds_entitlement_` + unit on `release_visible_to_org` |
