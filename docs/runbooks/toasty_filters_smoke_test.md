# Runbook -- Toasty filtered queries

> Manual validation after shipping **SQL-backed list/search/entitlement
> paths** (status/channel/org `in_list`, `ilike` search, `limit`/`offset`/
> `count`, seats `.count()`, companies two-phase search) plus **deferred
> body**. CI covers unit / invariants / proptest / battle / in-process E2E
> against `vcp_test`; staging proves browser HTTPS and denial paths.
>
> Audience: release / staging operators.
> Severity: **BLOCKING** for this surface. Do not ship without A–C.

Related:

- [README](../../README.md) (seed login, route map)
- Lint: `scripts/check_toasty_filters.sh`
- Pyramid: `.cursor/rules/vcp-test-pyramid.mdc`
- Filter: `cargo test --test integration_tests -- toasty_filters -- --test-threads=1`
- Auth denials: [`auth_tenant_smoke_test.md`](auth_tenant_smoke_test.md)

## Automated prerequisites

```bash
bash scripts/setup_test_db.sh   # or: just db-create-test
rtk cargo fmt --all -- --check
rtk cargo clippy --all-targets -- -D warnings
bash scripts/check_toasty_filters.sh
bash scripts/check_request_sql_dedup.sh
rtk cargo test --test integration_tests -- toasty_filters -- --test-threads=1
rtk cargo test --test integration_tests -- request_sql_dedup -- --test-threads=1
```

## Lab prerequisites

- `VCP_ENVIRONMENT=development` + `just run` (HTTPS `https://127.0.0.1:3000`).
- Browser or `curl -k` willing to accept the local self-signed cert.
- Seed users: `support@vauban.sh` / `password` (staff),
  `l.martin@acme.example` / `password` (member); org `acme-infrastructure`.

## A -- Happy path

1. Sign in as `support@vauban.sh` / `password` (or member where appropriate).
2. Exercise the surface on `/acme-infrastructure/…` per product IA.
3. Confirm expected success status / visible data.
4. Spot-check lists (docs, issues, builds, admin companies) page and
   search without full-table Rust filtering regressions.

Pass: surface behaves as in the focused E2E suite.

## B -- Denial paths

1. As `l.martin@acme.example`, confirm admin-only routes return **404**.
2. While authenticated, open a non-member org slug — expect **404**.
3. Anonymous / expired session must not leak tenant data.

Pass: Casbin + tenant fail-closed.

## C -- SQL-path smoke notes

1. Builds list: only GA + own-org **published** rows (SQL tenant net);
   foreign private versions 404 on detail/download.
2. Issues/docs search: `q` with `%` / `_` still matches literally
   (escaped `ilike`); pager uses SQL `limit`/`offset`.
3. Admin companies: empty `q` pages in SQL; non-empty `q` finds by
   org fields **or** account email (two-phase); seat count is SQL
   `COUNT(*)`.
4. Release version order remains Rust `cmp_version_desc` after the
   SQL-bounded set (intentional semver exception).
5. List GET (docs / issues / admin companies) with DEBUG: **one** COUNT
   (or one companies hydrate) per filter key for page+embedded shard —
   not two. Shard-only POSTs to `/_topcoat/runtime/shards/…` still re-auth and
   query (separate request). Lint: `scripts/check_request_sql_dedup.sh`.
6. Org dashboard (`/{org}`): **one** org-scoped issues SELECT (not four
   issue `COUNT(*)`); docs tile may still `COUNT` published articles.
   Lint: `scripts/check_dashboard_stats.sh`. See
   [`dashboard_stats_smoke_test.md`](dashboard_stats_smoke_test.md).

Pass: no cross-tenant rows; search/paging match automated pyramid.

## Related automated coverage

| Layer | Filter / artifact |
|-------|-------------------|
| Invariants | `inv_`, `scripts/check_toasty_filters.sh` |
| Proptest | `prop_` |
| Battle | `battle_` |
| E2E | `e2e_` (`--test integration_tests`) |
