# Runbook -- Auth / tenant isolation smoke test

> Manual validation after shipping **auth, session, membership, and
> org-scoped Casbin gates**. CI covers unit / invariants / proptest /
> battle / in-process E2E against `vcp_test`; staging proves browser
> HTTPS, cookies, and denial paths end-to-end.
>
> Audience: release / staging operators.
> Severity: **BLOCKING** for portal auth / tenant changes. Do not ship
> without A–D.

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
- Seed users (empty DB): `support@vauban.sh` / `password` (Vauban Support,
  `portal_role=admin`, reserved org `vauban`),
  `l.martin@acme.example` / `password` (`portal_role=org`, membership
  `role:org` on `acme-infrastructure`).
- `users.portal_role` is closed: only `admin` | `org` (CHECK + app helpers).

## A -- Login calm

1. Open `https://127.0.0.1:3000/login` (trust self-signed if prompted).
2. Sign in as `support@vauban.sh` / `password`.
3. Expect redirect to `/vauban` dashboard (200) — staff preview home.
4. Confirm left rail shows preview links under `/vauban/…` plus an
   **ADMIN** block linking `/admin/issues`, `/admin/docs`, …
5. Sign out; sign in as `l.martin@acme.example` / `password`.
6. Expect redirect to `/acme-infrastructure` with no ADMIN rail.

Pass: staff lands on reserved preview org; client lands on their org.

## A2 -- Session entry (no Continue button)

1. While still signed in as `l.martin@acme.example`, open `/` and `/login`.
2. Expect an immediate redirect to `/acme-infrastructure` (no login form,
   no "Continue to portal" button).
3. Sign out; sign in as `support@vauban.sh`; open `/` and `/login`.
4. Expect redirect to `/vauban` in both cases.
5. With no cookie (private window), open `/` — expect redirect to `/login`
   and the sign-in form.

Pass: valid sessions skip `/` and `/login` chrome; anonymous `/` → login.

## B -- Wrong org (anti-enumeration)

1. While logged in as the staff seed user, open
   `https://127.0.0.1:3000/not-a-real-org`.
2. Expect **404** (not 403, not another org's data).
3. As `l.martin@acme.example`, open `/vauban` — expect **404**
   (reserved org is staff-only).
4. As `l.martin@acme.example`, open an **existing** other company slug
   (if present) and an invented slug — both **404**, same answer.

Pass: no cross-tenant leak / existence oracle via chatty errors.

## C -- Admin nest anti-enumeration

1. Sign in as `l.martin@acme.example` / `password`.
2. Open `https://127.0.0.1:3000/admin` and `/admin/docs`.
3. Expect **404** (same as an unknown path — not 403).
4. Anonymous GET `/admin/issues` — expect **404** as well.
5. As the client, POST `/admin/companies/new` with a dummy form — **404**.

Pass: clients and strangers get the same answer; `/admin/*` does not leak.

## D -- Login timing / rate limit (qualitative)

1. From a private window, POST wrong password for a real seed email and
   for a never-used email — both redirect to `/login` with the same form.
2. Repeat failed attempts against one email until the configured
   `[login]` lockout; response must still be redirect to `/login` (no
   distinct “locked” page).
3. Successful seed login still works after a calm period / process restart.

Pass: no obvious timing or message oracle; lockout is silent.

## Related automated coverage

| Layer | Filter / artifact |
|-------|-------------------|
| Invariants | `inv_`, `scripts/check_auth_tenant.sh` |
| Proptest | `prop_` |
| Battle | `battle_` |
| E2E | `e2e_` (`--test integration_tests`) |
