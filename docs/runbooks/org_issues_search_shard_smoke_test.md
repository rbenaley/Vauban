# Runbook -- Org issues search shard

> Manual validation after shipping **live org issues search** (Topcoat
> shard re-auth on every keystroke). CI covers unit / invariants /
> proptest / battle / in-process E2E against `vcp_test`; staging proves
> browser HTTPS, Network POSTs to `/_topcoat/shards/…`, and denial paths.
>
> Audience: release / staging operators.
> Severity: **BLOCKING** for this surface. Do not ship without A–B.

Related:

- [README](../../README.md) (seed login, route map)
- Lint: `scripts/check_org_issues_search_shard.sh`
- Pure helpers: `src/issues_search.rs`
- Pyramid: `.cursor/rules/vcp-test-pyramid.mdc`
- Filter: `just test -- org_issues_search_shard`
- Auth denials: [`auth_tenant_smoke_test.md`](auth_tenant_smoke_test.md)
- Admin twin: [`admin_issues_search_shard_smoke_test.md`](admin_issues_search_shard_smoke_test.md)

## Automated prerequisites

```bash
bash scripts/setup_test_db.sh   # or: just db-create-test
just fmt-check
just clippy
bash scripts/check_org_issues_search_shard.sh
just test -- org_issues_search_shard
```

## Lab prerequisites

- `VCP_ENVIRONMENT=development` + `just run` (HTTPS `https://127.0.0.1:3000`).
- Browser DevTools Network panel (filter `shards`) or `curl -k`.
- Seed member: `l.martin@acme.example` / `password` on `acme-infrastructure`.
- Confirm `just run` terminal is visible for panics.

## A -- Live search happy path

1. Sign in as `l.martin@acme.example` / `password`.
2. Open `/acme-infrastructure/issues`.
3. Open DevTools → Network; filter on `/_topcoat/shards`.
4. Type a fragment of a known issue title or key gradually.
5. Confirm POSTs to `/_topcoat/shards/{id}` return **200** (not 500).
6. Confirm the issue list updates without a full page reload.
7. Confirm no `path parameter "org" was not found` panic in the server log.
8. Clear the field — full org issue list returns.

Pass: shard POSTs stay 200; UI updates; no worker panics.

## B -- Denial paths (fail-closed)

1. Body `org_slug` empty / whitespace → **404**.
2. Body `org_slug` set to another org the user does not belong to → **404**.
3. Same POST without session cookie → **404**.
4. Membership with an unknown role (no Casbin `issues,read`) → **403**.

Pass: forged tenant / anon / missing permission never leak issue HTML.

## Related automated coverage

| Layer | Filter / artifact |
|-------|-------------------|
| Unit | `issues_search_*` in `src/issues_search.rs` |
| Invariants | `inv_`, `scripts/check_org_issues_search_shard.sh` |
| Proptest | `prop_` |
| Battle | `battle_parallel_org_issues_search_shard_posts_return_200` |
| E2E | `e2e_org_issues_search_shard_*` |
| Smoke | this runbook (A–B) |
