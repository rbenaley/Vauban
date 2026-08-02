# Runbook -- Admin issues search shard

> Manual validation after shipping **live admin issues search** on
> `/admin/issues` (Topcoat shard re-auth on every keystroke for `q` and
> `org`). CI covers unit / invariants / proptest / battle / in-process E2E
> against `vcp_test`; staging proves browser HTTPS and denial paths.
>
> Audience: release / staging operators.
> Severity: **BLOCKING** for this surface. Do not ship without A–B.

Related:

- [README](../../README.md) (seed login, route map)
- Lint: `scripts/check_admin_issues_search_shard.sh`
- Pure helpers: `src/issues_search.rs`
- Pyramid: `.cursor/rules/vcp-test-pyramid.mdc`
- Filter: `just test -- admin_issues_search_shard`
- Org twin: [`org_issues_search_shard_smoke_test.md`](org_issues_search_shard_smoke_test.md)
- Auth denials: [`auth_tenant_smoke_test.md`](auth_tenant_smoke_test.md)

## Automated prerequisites

```bash
bash scripts/setup_test_db.sh   # or: just db-create-test
just fmt-check
just clippy
bash scripts/check_admin_issues_search_shard.sh
just test -- admin_issues_search_shard
```

## Lab prerequisites

- `VCP_ENVIRONMENT=development` + `just run` (HTTPS `https://127.0.0.1:3000`).
- Browser DevTools Network panel (filter `shards`) or `curl -k`.
- Seed staff: `support@vauban.sh` / `password`.
- Seed member (denial): `l.martin@acme.example` / `password`.

## A -- Live search happy path

1. Sign in as `support@vauban.sh` / `password`.
2. Open `https://127.0.0.1:3000/admin/issues`.
3. Open DevTools → Network; filter on `/_topcoat/shards`.
4. Type into **Search (ID, title)** — confirm POSTs return **200** and
   the list filters without a full reload.
5. Type an org slug into **Org slug or id** — confirm the list narrows
   to that org (still **200**).
6. Confirm server logs show no shard / path-param panics.
7. Clear both fields — aggregated list returns.

Pass: shard POSTs stay 200; both filters update live; no panics.
Org chip resolves slug→id in SQL; status/`q`/`limit`/`offset`/`count`
are pushed into Toasty (not full-table Rust match).

## B -- Denial paths (fail-closed)

1. Same shard POST without cookie → **404**.
2. As `l.martin@acme.example`, POST to a captured shard path → **404**.
3. Confirm denial bodies do not include foreign issue titles/keys.

Pass: staff-only; fail-closed without data leak.

## C -- Pagination

SSR list paging (10 rows per page, shareable `?page=`).

1. With **11+** matching issues (search or unfiltered), open
   `/admin/issues` — expect at most **10** rows, pager on the **same row
   as the status chips**.
2. Follow **Next** (or `?page=2`) — expect the remainder only.
3. From page 2, click a **status** chip (or **All**) — URL must **not**
   keep `page=` (reset to page 1).

Pass: 10 max per page; chip-row pager; filter chips omit `page=`.

## Related automated coverage

| Layer | Filter / artifact |
|-------|-------------------|
| Unit | `issues_search_*` in `src/issues_search.rs` |
| Invariants | `inv_`, `scripts/check_admin_issues_search_shard.sh` |
| Proptest | `prop_` |
| Battle | `battle_parallel_admin_issues_search_shard_posts_return_200` |
| E2E | `e2e_admin_issues_search_shard_*` |
| Smoke | this runbook (A–B) |
