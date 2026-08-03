# VCP — Vauban Customer Portal

Authenticated customer portal for Vauban.

## Stack

- [Topcoat](https://github.com/tokio-rs/topcoat) 0.5 (SSR, module router, sessions, Tailwind, `mail` + `mail-smtp`)
- [Toasty](https://github.com/tokio-rs/toasty) 0.9 + PostgreSQL
- Casbin-format policy file under `config/access/` (custom loader; tenant gate on `{org}`)
- TOML configuration under `config/` (same layering model as Vauban)
- **HTTPS only** — TLS 1.3 via rustls; optional ACME TLS-ALPN-01 (no HTTP listener)
- Passwordless magic-link login (SMTP): Mailpit in development/testing; Scaleway TEM in production (`[mail]` / `[magiclinks]`)

## Prerequisites

- Rust 1.95+ (see `rust-toolchain.toml`)
- [just](https://github.com/casey/just)
- PostgreSQL listening locally

Create databases:

```bash
just db-create        # local app DB `vcp`
just db-create-test   # automated tests DB `vcp_test` (or: bash scripts/setup_test_db.sh)
```

`just validate` / `just test` call `ensure-vcp-test` and provision
`vcp_test` (role + DB) on first use when the connection check fails.
Manual `just db-create-test` remains available.

## Configuration

Application settings live in TOML files under `config/`. There is **no** `.env`
for app config.

| File | When |
|------|------|
| `config/default.toml` | Base (non-production) |
| `config/development.toml` | Dev overlay |
| `config/testing.toml` | Test overlay |
| `config/local.toml` | Personal overrides (gitignored; copy from `local.toml.example`) |
| `config/vcp.conf` | **Production only** (self-contained; no merge with `default.toml`) |

Environment selection:

```bash
export VCP_ENVIRONMENT=development   # layered TOML
# unset or production               # loads config/vcp.conf only
```

Config directory lookup:

1. `VCP_CONFIG_DIR` (if set)
2. `{crate}/config` (this repo)
3. `/usr/local/etc/vcp`

Production install path: `/usr/local/etc/vcp/vcp.conf` (plus `access/` policies and TLS material).

Notable knobs (see TOML / `vcp.conf`):

| Key | Role |
|-----|------|
| `[org] max_accounts_per_org` | Seat cap for client company portal accounts (default **5**) |
| `[org] max_lts_subscriptions` | Cap for LTS / Industrial LTS steppers on admin companies (default **99**) |

### TLS

- Cleartext HTTP is **forbidden**. The process binds HTTPS only.
- Dev: on first boot, a self-signed cert is written to `certs/dev-server.{crt,key}` (gitignored).
- Prod: configure `[server.tls]` PEM paths; enable `[server.tls.acme]` for automatic
  issuance/renewal (TLS-ALPN-01, renews `renew_before_hours` before expiry, default 24h,
  hot-activates without restart).
- `public_origins` must be `https://…` only.

Optional personal DB URL:

```bash
cp config/local.toml.example config/local.toml
# edit [database].url
```

## Run

```bash
just build            # cargo build + rebundle assets if needed (profile-aware)
just run              # just build + HTTPS on https://127.0.0.1:3000
just run --release    # same with release binary + matching asset bundle
just release          # cargo build --release + force asset bundle (no run)
just validate         # fmt + rustfmt --check + clippy + ensure-vcp-test + tests
just test             # ensure-vcp-test + test-profile asset bundle + cargo test
just fmt              # cargo fmt + topcoat fmt
just fmt-check        # pure check (rewrites nothing if already clean)
just clippy           # clippy with warnings as errors
just bundle           # cargo build + force topcoat asset bundle → target/assets
just bundle --release # release binary + force asset bundle
just dev              # topcoat HMR (no custom TLS); prefer just run for HTTPS
just db-migrate       # apply pending Toasty migrations (dev DB)
just db-reset         # drop/recreate local `vcp` + migrate (destructive)
just db-reset-test    # drop/recreate `vcp_test` (destructive)
```

Recipes that need the Topcoat CLI (`run`, `bundle`, `release`, `fmt`,
`validate`, `dev`, …) call `ensure-topcoat`, which installs the pinned
`topcoat-cli` 0.5.0 on first use when `topcoat` is missing from `PATH` /
`$CARGO_HOME/bin`. No manual `cargo install` and no prior `just validate`
are required before `just run`.

`just run` / `just build` keep the asset catalog in sync: they rebundle
when `target/{debug,release}/vcp` is newer than
`target/assets/manifest.toml`, the manifest is missing, or the last bundle
was for another Cargo profile (stamp `target/assets/.bundle-profile`).
`just test` / `just validate` always bundle from the Cargo **test**
profile so integration-test AssetIds match; a later `just run` detects
the profile change and rebundles debug/release. Use `just bundle` to
force a refresh. Prefer these over bare `cargo run` / `cargo build`:
Topcoat 0.5 Tailwind AssetIds embed `OUT_DIR`, so a rebuild without a
matching manifest panics when resolving CSS / icons / the runtime
script. Boot also fails closed if the catalog is stale. Pass `--release`
through `just run` / `just build` / `just bundle` so binary and asset IDs
stay matched. `just run` keeps VCP’s custom TLS 1.3 serve path;
`topcoat dev` / `just dev` is UI HMR only.

Smoke against a self-signed cert:

```bash
curl -k https://127.0.0.1:3000/login
```

Browsers will warn on the self-signed cert until you trust it or use ACME in staging.

### Login (magic links)

`/login` is email-only. Submitting the form swaps in-place to a **Check your
email** panel (Topcoat signals + procedure; no `/login/check-email` redirect)
with a resend cooldown of `magiclinks.token_ttl_secs` shown as `MM:SS`. A
one-shot link is emailed via SMTP. Local development expects
[Mailpit](https://github.com/axllent/mailpit) (or equivalent) on
`localhost:1025` (`[mail]` in `development.toml`).

After opening a valid link: staff land on `/vauban`; a single client membership
goes to `/{org}`; multiple client memberships open `/choose-org` to pick a
tenant (then `/{org}`). Authenticated `GET /` and `GET /login` use the same
landing rules.

| Email | Notes |
|-------|--------|
| `magiclinks.vcp_admin` (default `support@vauban.sh`) | JIT-created on first sign-in as `portal_role=admin`, display name `Vauban Support`; lands on `/vauban` |
| Company account emails | Provisioned from `/admin/companies` (invitation on create/revive; org-scoped revocation mail on remove; soft-deleted when orphaned) |

Demo seed (empty DB) still creates `l.martin@acme.example` on `acme-infrastructure` for catalog samples — sign in via magic link.

Slug **`vauban`** is reserved (not a billable client). Client companies cannot create or rename to that slug.

Ops smoke: [`docs/runbooks/magic_links_smoke_test.md`](docs/runbooks/magic_links_smoke_test.md).

## Route map

| Path | Surface |
|------|---------|
| `/login` | Sign in |
| `/choose-org` | Multi-org picker (session required) |
| `/{org}` | Dashboard (clients + staff preview on `vauban`) |
| `/{org}/docs` | Documentation KB (shared catalogue) |
| `/{org}/builds` | Builds (GA + that org's private releases) |
| `/{org}/issues` | Client issue tracker (**not** for slug `vauban`) |
| `/{org}/account` | Account & subscription |
| `/admin` | Admin hub (redirects to `/admin/issues`) |
| `/admin/issues` | Aggregated issues (staff; optional org filter) |
| `/admin/docs` | Documentation editor |
| `/admin/releases` | Release manager (GA or org-targeted) |
| `/admin/companies` | Client companies: list / new / edit / delete (excludes reserved `vauban`) |
| `/admin/companies/new` | Onboard org + provision email-only accounts (Mailbox syntax check; invitation magic link on create) |
| `/admin/companies/{id}` | Edit company + sync accounts under `org.max_accounts_per_org` |

Wrong org slug → **404** (no cross-tenant leak). `/admin/*` requires Vauban Support (`portal_role=admin` + Casbin `admin:view`). Direct `/vauban/issues*` redirects to `/admin/issues`.

## Validate

```bash
just validate         # fmt + rustfmt --check + clippy + ensure-vcp-test + tests
```



Structural lints (also exercised via `*_invariants_test`):

```bash
bash scripts/check_auth_tenant.sh
bash scripts/check_http_edge.sh
bash scripts/check_portal_shell.sh
bash scripts/check_no_unicode_icons.sh
bash scripts/check_admin_docs.sh
bash scripts/check_portal_issues.sh
bash scripts/check_admin_releases.sh
bash scripts/check_admin_companies.sh
bash scripts/check_org_account.sh
bash scripts/check_builds_entitlement.sh
bash scripts/check_toasty_filters.sh
bash scripts/check_request_sql_dedup.sh
bash scripts/check_dashboard_stats.sh
bash scripts/check_docs_search_shard.sh
bash scripts/check_display_tz.sh
```

Staging smoke runbooks live under [`docs/runbooks/`](docs/runbooks/).
After model/schema changes, reset the test DB: `just db-reset-test`.
