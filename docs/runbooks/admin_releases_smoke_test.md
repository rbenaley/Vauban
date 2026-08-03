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
   **with a package file** so `vcp-store` commits the blob and
   `storage_objects` is upserted (no package → row stays **HIDDEN**).
3. On `/admin/releases`, confirm STATUS shows a green **PUBLISHED** badge,
   SIGNATURE shows a full 64-hex digest from `storage_objects`, and
   ACTIONS has **Edit** / **Unpublish** / Delete (trash).
4. Publish an org-targeted hotfix; confirm TARGET column on the list.
5. Click **Unpublish** — STATUS becomes amber **HIDDEN**. Confirm the version is
   absent under `/{org}/builds`, `/vauban/builds`, and the dashboard latest-build
   card on `/vauban` (and `/{org}`). Manage HIDDEN rows only on `/admin/releases`.
   List order is SQL semver (`ORDER BY` sort columns) — publish toggle must not
   reshuffle relative version order among remaining rows.
6. Click **Publish** — builds + dashboard show the version again.
7. Open **Edit** (`/admin/releases/{id}`), change notes/channel, Save — list
   reflects the update.
8. Delete via trash → type `delete` → **Delete permanently**; row is gone.

Pass: surface behaves as in the focused E2E suite.

## B -- Denial paths

1. As `l.martin@acme.example`, confirm `/admin/releases` returns **404**.
2. Member POSTs to `/admin/releases/{id}/publish|unpublish|delete` → **404**.
3. While authenticated, open a non-member org slug — expect **404**.
4. Anonymous / expired session must not leak tenant data.

Pass: Casbin + tenant fail-closed.

## C -- Pagination

SSR list paging (10 rows per page, shareable `?page=`).

1. With **11+** releases in `/admin/releases`, expect at most **10** table
   rows and a right-aligned **toolbar pager** above the table.
2. Follow **Next** (or `?page=2`) — expect the remainder only.
3. Pager links must **not** sticky-carry `?delete=` / `err=`.

Pass: 10 max per page; toolbar pager.

## Related automated coverage

| Layer | Filter / artifact |
|-------|-------------------|
| Invariants | `inv_`, `scripts/check_admin_releases.sh` |
| Proptest | `prop_` |
| Battle | `battle_` |
| E2E | `e2e_` (`--test integration_tests`) |
| Builds visibility | `builds_entitlement_` + unit on `release_visible_to_org` |
