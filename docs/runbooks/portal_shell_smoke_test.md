# Runbook -- Portal shell chrome (layouts / rail / topbar)

> Manual validation after shipping **Topcoat layouts**, org rail/topbar, or
> nav crumb mapping. Auth denials stay in
> [`auth_tenant_smoke_test.md`](auth_tenant_smoke_test.md).
>
> Audience: release / staging operators.
> Severity: **BLOCKING** for shell/chrome changes. Do not ship without A–C.

Related:

- [README](../../README.md)
- Lint: `scripts/check_portal_shell.sh`
- Pyramid: `.cursor/rules/vcp-test-pyramid.mdc`
- Filter: `cargo test --test integration_tests -- portal_shell -- --test-threads=1`
- Auth denials: [`auth_tenant_smoke_test.md`](auth_tenant_smoke_test.md)

## Automated prerequisites

```bash
bash scripts/setup_test_db.sh   # or: just db-create-test
just fmt-check
rtk cargo clippy --all-targets -- -D warnings
bash scripts/check_portal_shell.sh
rtk cargo test --test integration_tests -- portal_shell -- --test-threads=1
```

## Lab prerequisites

- `VCP_ENVIRONMENT=development` + `just run` (HTTPS `https://127.0.0.1:3000`).
- Browser or `curl -k`.
- Seed: `support@vauban.sh` / `password` (staff → `/vauban`),
  `l.martin@acme.example` / `password` (client → `/acme-infrastructure`).

## A -- Login splash chrome

1. Open `https://127.0.0.1:3000/login`.
2. Expect VAUBAN brand splash (`vb-login-*`) and Sign in form.

Pass: login page shows branded splash, not a bare form on a blank page.

## B -- Org shell chrome

1. Sign in as `support@vauban.sh` / `password`.
2. On `/vauban`, expect left rail + topbar crumb and an **ADMIN** rail
   block. Primary Issues link and admin Issues both go to `/admin/issues`
   (not `/vauban/issues`).
3. Sign out; sign in as `l.martin@acme.example` / `password`.
4. Expect shell chrome on `/acme-infrastructure` **without** the ADMIN
   rail block; Issues → `/{org}/issues`.

Pass: staff sees ADMIN rail + Issues → `/admin/issues`; client has no ADMIN.

## C -- UI polish

Concept CSS polish on authenticated chrome (no Framer / client motion libs).

1. On org home, open a page with a countdown or large figure (builds
   ephemeral panel after generating a link, or dashboard stat values).
   Digits must not jitter as values change (`tabular-nums`).
2. Navigate between org sections (home → builds → docs). Expect **no**
   full-screen fade on every page (`vb-screen` must not use `vbIn`).
3. Press a primary `vb-btn` (link or button). Expect a slight press
   scale (~0.96); disabled `span.vb-btn` should not scale.
4. Open a docs article modal: close control must be easy to hit (≥40px).
   On an active ephemeral panel, Revoke must likewise be easy to click.

Pass: countdown digits stable; nav without full-page fade; button press
scale; modal close / revoke easy to click.
