# Runbook -- Admin client companies

> Manual validation after shipping **Concept companies** (list/edit,
> email-only accounts, configurable `org.max_accounts_per_org`, default 5).
> CI covers unit / invariants / proptest / battle / in-process E2E against
> `vcp_test`; staging proves browser HTTPS and denial paths.
>
> Audience: release / staging operators.
> Severity: **BLOCKING** for this surface. Do not ship without A–B.

Related:

- [README](../../README.md) (seed login, route map)
- Lint: `scripts/check_admin_companies.sh`
- Pyramid: `.cursor/rules/vcp-test-pyramid.mdc`
- Filter: `cargo test --test integration_tests -- admin_companies -- --test-threads=1`
- Auth denials: [`auth_tenant_smoke_test.md`](auth_tenant_smoke_test.md)

## Automated prerequisites

```bash
bash scripts/setup_test_db.sh   # or: just db-create-test
rtk cargo fmt --all -- --check
rtk cargo clippy --all-targets -- -D warnings
bash scripts/check_admin_companies.sh
rtk cargo test --test integration_tests -- admin_companies -- --test-threads=1
```

## Lab prerequisites

- `VCP_ENVIRONMENT=development` + `just run` (HTTPS `https://127.0.0.1:3000`).
- Browser or `curl -k` willing to accept the local self-signed cert.
- Seed users: staff `support@vauban.sh` / `password` (lands on `/vauban`);
  client `l.martin@acme.example` / `password` on `acme-infrastructure`.

## A -- Happy path

1. Sign in as `support@vauban.sh` / `password`.
2. Open `/admin/companies` — expect Concept cards (contact, ADDRESS/VAT,
   USER ACCOUNTS pills, Edit + trash). No reserved `vauban` card.
3. Click **+ New company**; add company fields and up to N email-only
   accounts (no password fields). Save.
4. Confirm list shows email pills; open Edit; add/remove an email; Save.
5. Delete via trash + type `delete`.
6. Confirm slug/name `Vauban` is rejected on create.

Pass: surface matches Concept; seat cap comes from config (default 5).

## B -- Denial paths

1. As `l.martin@acme.example`, confirm `/admin/companies` returns **404**.
2. While authenticated, open a non-member org slug — expect **404**.
3. Anonymous / expired session must not leak tenant data.
4. On **+ New company**, enter a USER ACCOUNTS value like `not-an-email`
   and Save — expect form error `Invalid email address`, no new card.

Pass: Casbin + tenant fail-closed; Mailbox syntax validation fail-closed.

## Related automated coverage

| Layer | Filter / artifact |
|-------|-------------------|
| Invariants | `inv_`, `scripts/check_admin_companies.sh` |
| Proptest | `prop_` |
| Battle | `battle_` |
| E2E | `e2e_` (`--test integration_tests`) |
