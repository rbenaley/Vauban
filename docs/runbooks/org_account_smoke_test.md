# Runbook -- Org account & subscription page

> Manual validation after shipping `/{org}/account` company-fiche parity
> (address, VAT, LTS counts, member pills). Auth denials stay in
> [`auth_tenant_smoke_test.md`](auth_tenant_smoke_test.md).
>
> Audience: release / staging operators.
> Severity: **BLOCKING** for account-page / company-profile changes.

Related:

- [README](../../README.md)
- Lint: `scripts/check_org_account.sh`
- Companies admin: [`admin_companies_smoke_test.md`](admin_companies_smoke_test.md)
- Pyramid: `.cursor/rules/vcp-test-pyramid.mdc`
- Filter: `just test --test integration_tests -- org_account -- --test-threads=1`

## Automated prerequisites

```bash
bash scripts/setup_test_db.sh   # or: just db-create-test
just fmt-check
rtk cargo clippy --all-targets -- -D warnings
bash scripts/check_org_account.sh
just test --test integration_tests -- org_account -- --test-threads=1
```

## Lab prerequisites

- `VCP_ENVIRONMENT=development` + `just run` (HTTPS `https://127.0.0.1:3000`).
- Seed client: `l.martin@acme.example` / `password` → `/acme-infrastructure`.
- Or a company created via `/admin/companies` with a fiche account.

## A -- Fiche parity

1. Sign in as an org member; open `/{org}/account`.
2. Expect company **name**, **plan**, **status**, **address**, **VAT**,
   technical contact, **Vauban LTS** / **Industrial LTS** counts, and
   **USER ACCOUNTS** pills matching `/admin/companies` for that org.
   SUBSCRIPTION must **not** show Supported builds.
3. No **SIGNED-IN USER** mockup block — only company fiche + **Sign out**.

Pass: values match the admin company fiche / Organization row (not mockup).

## B -- Denial paths

1. Anonymous GET `/{org}/account` → **404**.
2. Authenticated member of org A opening org B `/{other}/account` → **404**.

Pass: Casbin `account_read` + tenant membership fail-closed.

## Related automated coverage

| Layer | Filter / artifact |
|-------|-------------------|
| Invariants | `inv_`, `scripts/check_org_account.sh` |
| Proptest | `prop_` |
| Battle | `battle_` |
| E2E | `e2e_` (`--test integration_tests`) |
