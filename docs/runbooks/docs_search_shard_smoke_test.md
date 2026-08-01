# Runbook -- Docs search shard

> Manual validation after shipping **live docs search** (Topcoat shard
> re-auth on every keystroke). CI covers unit / invariants / proptest /
> battle / in-process E2E against `vcp_test`; staging proves browser
> HTTPS, Network POSTs to `/_topcoat/shards/…`, and denial paths.
>
> Audience: release / staging operators.
> Severity: **BLOCKING** for this surface. Do not ship without A–B.

Related:

- [README](../../README.md) (seed login, route map)
- Lint: `scripts/check_docs_search_shard.sh`
- Pure helpers: `src/docs_search.rs`
- Pyramid: `.cursor/rules/vcp-test-pyramid.mdc`
- Filter: `just test -- docs_search_shard`
- Auth denials: [`auth_tenant_smoke_test.md`](auth_tenant_smoke_test.md)

## Automated prerequisites

```bash
bash scripts/setup_test_db.sh   # or: just db-create-test
just fmt-check
just clippy
bash scripts/check_docs_search_shard.sh
just test -- docs_search_shard
```

## Lab prerequisites

- `VCP_ENVIRONMENT=development` + `just run` (HTTPS `https://127.0.0.1:3000`).
- Browser DevTools Network panel (filter `shards`) or `curl -k`.
- Seed users: `support@vauban.sh` / `password` (staff),
  `l.martin@acme.example` / `password` (member); org `acme-infrastructure`.
- Confirm server logs are visible (`just run` terminal) so panics are obvious.

## A -- Live search happy path

1. Sign in as `l.martin@acme.example` / `password`.
2. Open `/acme-infrastructure/docs`.
3. Open DevTools → Network; filter on `/_topcoat/shards`.
4. Type `ssh` gradually into the search field (do not submit the form).
5. Confirm POSTs to `/_topcoat/shards/{id}` return **200** (not 500).
6. Confirm the article list updates without a full page reload.
7. Confirm the `just run` terminal shows **no**
   `path parameter "org" was not found` panic.
8. Clear the field — full published list returns.

Pass: shard POSTs stay 200; UI updates; no worker panics.

## B -- Denial paths (fail-closed)

Replay a captured shard POST (or use the in-process E2E as the oracle):

1. Body `org_slug` empty / whitespace → **404**, no article HTML.
2. Body `org_slug` set to another existing org the user does not belong
   to → **404**, no foreign titles/slugs.
3. Same POST without session cookie → **404**.
4. Membership with an unknown role (no Casbin `docs,read`) → **404**
   (capability entry; anti-enumeration).

Pass: forged tenant / anon / missing permission never leak docs HTML.

## C -- Pagination

SSR list paging (10 rows per page, shareable `?page=`).

1. With **11+** matching articles (or a search that yields 11+), open
   `/{org}/docs` — expect at most **10** rows, pager on the **same row as
   the category chips** (chips left, pager right).
2. Follow **Next** (or `?page=2`) — expect the remainder only.
3. From page 2, click a **category** chip (or **All**) — URL must **not**
   keep `page=` (reset to page 1). Live search keystrokes also reset to
   page 1.

Pass: 10 max per page; chip-row pager; filter chips omit `page=`.

## Related automated coverage

| Layer | Filter / artifact |
|-------|-------------------|
| Unit | `docs_search_shard_*` in `src/docs_search.rs` |
| Invariants | `inv_`, `scripts/check_docs_search_shard.sh` |
| Proptest | `prop_` (+ unit `docs_search_shard_prop_*`) |
| Battle | `battle_parallel_docs_search_shard_posts_return_200` |
| E2E | `e2e_docs_search_shard_*` denials + match |
| Smoke | this runbook (A–B) |
