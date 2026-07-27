# Runbook -- Builds download entitlement

> Manual validation after shipping **authorized 501 download stub** and
> **GA vs org-private release visibility**. CI covers unit / invariants /
> proptest / battle / in-process E2E against `vcp_test`; staging proves
> browser HTTPS and denial paths.
>
> Audience: release / staging operators.
> Severity: **BLOCKING** for this surface. Do not ship without A–C.

Related:

- [README](../../README.md) (seed login, route map)
- Lint: `scripts/check_builds_entitlement.sh`
- Pyramid: `.cursor/rules/vcp-test-pyramid.mdc`
- Filter: `cargo test --test integration_tests -- builds_entitlement -- --test-threads=1`
- Auth denials: [`auth_tenant_smoke_test.md`](auth_tenant_smoke_test.md)

## Automated prerequisites

```bash
bash scripts/setup_test_db.sh   # or: just db-create-test
rtk cargo fmt --all -- --check
rtk cargo clippy --all-targets -- -D warnings
bash scripts/check_builds_entitlement.sh
rtk cargo test --test integration_tests -- builds_entitlement -- --test-threads=1
```

## Lab prerequisites

- `VCP_ENVIRONMENT=development` + `just run` (HTTPS `https://127.0.0.1:3000`).
- Browser or `curl -k` willing to accept the local self-signed cert.
- Seed users: staff `support@vauban.sh` / `password`; client
  `l.martin@acme.example` / `password` on `acme-infrastructure`.
- Seed includes GA releases plus an Acme-private hotfix (`v0.8.6-acme1`).

## A -- Happy path

1. Sign in as `l.martin@acme.example` / `password`.
2. Open `/acme-infrastructure/builds` — expect GA builds **and** the
   Acme-private hotfix.
3. Download POST on a visible version returns **501**
   (`download not configured`) until artifact storage ships.

Pass: client sees GA + own private builds; download stub is 501.

## B -- Org-private isolation

1. As staff, publish (or confirm) a release targeted at another org only.
2. As `l.martin@acme.example`, confirm that private build does **not**
   appear under `/acme-infrastructure/builds`.
3. Direct detail/download URL for a foreign private version → **404**.

Pass: `organization_id` targeting is enforced on list/detail/download.

## C -- Denial paths

1. As client, confirm `/admin/releases` returns **403**.
2. While authenticated, open a non-member org slug — expect **404**.
3. Anonymous / expired session must not leak tenant data.

Pass: Casbin + tenant fail-closed.

## Related automated coverage

| Layer | Filter / artifact |
|-------|-------------------|
| Invariants | `inv_`, `scripts/check_builds_entitlement.sh` |
| Proptest | `prop_` |
| Battle | `battle_` |
| E2E | `e2e_` (`--test integration_tests`) |
