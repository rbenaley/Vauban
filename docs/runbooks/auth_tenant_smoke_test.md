# Runbook -- Auth / tenant isolation smoke test

> Manual validation after shipping **auth, session, membership, and
> org-scoped Casbin gates**. CI covers unit / invariants / proptest /
> battle / in-process E2E against `vcp_test`; staging proves browser
> HTTPS, cookies, and denial paths end-to-end.
>
> Audience: release / staging operators.
> Severity: **BLOCKING** for portal auth / tenant changes. Do not ship
> without A–C.

Related:

- [README](../../README.md) (seed login, route map)
- Plan: `.cursor/plans/vcp_test_pyramid_c64572e6.plan.md`
- Lint: `scripts/check_auth_tenant.sh`
- Pyramid: `.cursor/rules/vcp-test-pyramid.mdc`
- Shell chrome (layouts / rail): [`portal_shell_smoke_test.md`](portal_shell_smoke_test.md)

## Automated prerequisites

```bash
bash scripts/setup_test_db.sh   # or: just db-create-test
rtk cargo fmt --all -- --check
rtk cargo clippy --all-targets -- -D warnings
bash scripts/check_auth_tenant.sh
rtk cargo test -- --test-threads=1
# focused filter:
rtk cargo test --test integration_tests -- auth_tenant -- --test-threads=1
```

## Lab prerequisites

- Postgres with `vcp` (dev) and optionally `vcp_test` (already used above).
- `VCP_ENVIRONMENT=development` + `just run` (HTTPS `:3000`).
- Browser or `curl -k` willing to accept the local self-signed cert.
- Seed users (empty DB): `admin@acme.example` / `password` (admin),
  `l.martin@acme.example` / `password` (member); org `acme-infrastructure`.

## A -- Login calm

1. Open `https://127.0.0.1:3000/login` (trust self-signed if prompted).
2. Sign in as `admin@acme.example` / `password`.
3. Expect redirect to `/acme-infrastructure` dashboard (200).
4. Confirm left rail shows Admin entries for the admin user.

Pass: authenticated dashboard for a member org.

## B -- Wrong org (anti-enumeration)

1. While logged in as the admin seed user, open
   `https://127.0.0.1:3000/not-a-real-org`.
2. Expect **404** (not 403, not another org's data).

Pass: no cross-tenant leak / existence oracle via chatty errors.

## C -- Member denied admin nest

1. Sign out; sign in as `l.martin@acme.example` / `password`.
2. Open `https://127.0.0.1:3000/acme-infrastructure/admin`.
3. Expect **403** Forbidden (no admin rail useful access).

Pass: Casbin `admin:view` fail-closed for `member`.

## Related automated coverage

| Layer | Filter / artifact |
|-------|-------------------|
| Unit | `session_expiry`, `password_`, `perms::tests` |
| Invariants | `inv_`, `scripts/check_auth_tenant.sh` |
| Proptest | `prop_` |
| Battle | `battle_` |
| E2E | `e2e_` (`--test integration_tests`) |
