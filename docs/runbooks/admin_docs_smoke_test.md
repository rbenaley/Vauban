# Runbook -- Admin documentation editor

> Manual validation after shipping **admin docs create/publish, client published-only**. CI covers unit /
> invariants / proptest / battle / in-process E2E against `vcp_test`;
> staging proves browser HTTPS and denial paths.
>
> Audience: release / staging operators.
> Severity: **BLOCKING** for this surface. Do not ship without A–B.

Related:

- [README](../../README.md) (seed login, route map)
- Lint: `scripts/check_admin_docs.sh`
- Pyramid: `.cursor/rules/vcp-test-pyramid.mdc`
- Filter: `cargo test --test integration_tests -- admin_docs -- --test-threads=1`
- Auth denials: [`auth_tenant_smoke_test.md`](auth_tenant_smoke_test.md)

## Automated prerequisites

```bash
bash scripts/setup_test_db.sh   # or: just db-create-test
rtk cargo fmt --all -- --check
rtk cargo clippy --all-targets -- -D warnings
bash scripts/check_admin_docs.sh
rtk cargo test --test integration_tests -- admin_docs -- --test-threads=1
```

## Lab prerequisites

- `VCP_ENVIRONMENT=development` + `just run` (HTTPS `https://127.0.0.1:3000`).
- Browser or `curl -k` willing to accept the local self-signed cert.
- Seed users: `support@vauban.sh` / `password` (staff),
  `l.martin@acme.example` / `password` (member); org `acme-infrastructure`.

## A -- Happy path

1. Sign in as `support@vauban.sh` / `password` (or member where appropriate).
2. Open `/admin/docs` — list ACTIONS must show **Edit**, **Unpublish**/**Publish**, and trash **Delete** (no UPDATED column). STATUS badges: green **PUBLISHED**, amber **DRAFT** (same unpublished look as releases HIDDEN). Title rows show excerpt under the title.
3. Open compose (`+ New article` or Edit): form is **full width**, titled **Compose article**, with Category|Excerpt on one row and a tall Content field.
4. Click Delete on a disposable row → type `delete` → **Delete permanently**; article disappears from admin list and client KB if it was published.
5. Edit a **published** article: change the body, click **Publish new version** — expect redirect to the admin list, a new `vN+1` PUBLISHED row, previous version DRAFT, client `/docs/{slug}` showing the new body.

Pass: surface behaves as in the focused E2E suite.

## B -- Denial paths

1. As `l.martin@acme.example`, confirm admin-only routes return **404**.
2. While authenticated, open a non-member org slug — expect **404**.
3. Anonymous / expired session must not leak tenant data.

Pass: Casbin + tenant fail-closed.

## C -- Pagination

SSR list paging (10 rows per page, shareable `?page=`).

1. With **11+** articles in `/admin/docs`, expect at most **10** table
   rows and a right-aligned **toolbar pager** above the table (no chip
   row on this surface).
2. Follow **Next** (or `?page=2`) — expect the remainder only.
3. Confirm pager links stay on `/admin/docs?page=N` and do not sticky
   `delete=` / `err=` overlay params.

Pass: 10 max per page; toolbar pager; overlay query not sticky.

## Related automated coverage

| Layer | Filter / artifact |
|-------|-------------------|
| Invariants | `inv_`, `scripts/check_admin_docs.sh` |
| Proptest | `prop_` |
| Battle | `battle_` |
| E2E | `e2e_` (`--test integration_tests`) |
