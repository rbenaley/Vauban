# Runbook -- Browser timezone display

> Manual validation after shipping **vcp_tz cookie localizes admin docs times**. CI covers unit /
> invariants / proptest / battle / in-process E2E against `vcp_test`;
> staging proves browser HTTPS and denial paths.
>
> Audience: release / staging operators.
> Severity: **BLOCKING** for this surface. Do not ship without A–B.

Related:

- [README](../../README.md) (seed login, route map)
- Lint: `scripts/check_display_tz.sh`
- Pyramid: `.cursor/rules/vcp-test-pyramid.mdc`
- Filter: `cargo test --test integration_tests -- display_tz -- --test-threads=1`
- Auth denials: [`auth_tenant_smoke_test.md`](auth_tenant_smoke_test.md)

## Automated prerequisites

```bash
bash scripts/setup_test_db.sh   # or: just db-create-test
rtk cargo fmt --all -- --check
rtk cargo clippy --all-targets -- -D warnings
bash scripts/check_display_tz.sh
rtk cargo test --test integration_tests -- display_tz -- --test-threads=1
```

## Lab prerequisites

- `VCP_ENVIRONMENT=development` + `just run` (HTTPS `https://127.0.0.1:3000`).
- Browser or `curl -k` willing to accept the local self-signed cert.
- Seed users: `admin@acme.example` / `password` (admin),
  `l.martin@acme.example` / `password` (member); org `acme-infrastructure`.

## A -- Happy path

1. Sign in as `admin@acme.example` / `password` (or member where appropriate).
2. Open DevTools → Application → Cookies and confirm `vcp_tz` equals the browser IANA zone (e.g. `Europe/Brussels`).
3. Open `/acme-infrastructure/docs/quick-start` (hard refresh once if the cookie was just set). Confirm **Updated** shows local wall time (CEST/CET), not `UTC`.

Pass: surface behaves as in the focused E2E suite; visible times match the browser zone.

## B -- Denial paths

1. As `l.martin@acme.example`, confirm admin-only routes return **403**.
2. While authenticated, open a non-member org slug — expect **404**.
3. Anonymous / expired session must not leak tenant data.

Pass: Casbin + tenant fail-closed.

## Related automated coverage

| Layer | Filter / artifact |
|-------|-------------------|
| Invariants | `inv_`, `scripts/check_display_tz.sh` |
| Proptest | `prop_` |
| Battle | `battle_` |
| E2E | `e2e_` (`--test integration_tests`) |
