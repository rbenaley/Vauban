# VCP — Vauban Customer Portal

Authenticated customer portal for Vauban.

## Stack

- [Topcoat](https://github.com/tokio-rs/topcoat) 0.4 (SSR, module router, sessions, Tailwind)
- [Toasty](https://github.com/tokio-rs/toasty) 0.9 + PostgreSQL
- Casbin-format policy file under `config/access/` (custom loader; tenant gate on `{org}`)
- TOML configuration under `config/` (same layering model as Vauban)
- **HTTPS only** — TLS 1.3 via rustls; optional ACME TLS-ALPN-01 (no HTTP listener)

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
just run              # build + asset bundle + HTTPS on https://127.0.0.1:3000
just run --release    # same with release binary + matching asset bundle
just release          # cargo build --release + matching asset bundle (no run)
just validate         # fmt-check + clippy + ensure-vcp-test + bundle + tests
just test             # ensure-vcp-test + bundle + cargo test (--test-threads=1)
just fmt              # cargo fmt + topcoat fmt
just clippy           # clippy with warnings as errors
just bundle           # cargo build + topcoat asset bundle → target/assets
just bundle --release # release binary + matching asset bundle
just dev              # topcoat HMR (no custom TLS); prefer just run for HTTPS
just db-migrate       # apply pending Toasty migrations (dev DB)
just db-reset         # drop/recreate local `vcp` + migrate (destructive)
just db-reset-test    # drop/recreate `vcp_test` (destructive)
```

Recipes that need the Topcoat CLI (`run`, `bundle`, `release`, `fmt`,
`validate`, `dev`, …) call `ensure-topcoat`, which installs the pinned
`topcoat-cli` 0.4.0 on first use when `topcoat` is missing from `PATH` /
`$CARGO_HOME/bin`. No manual `cargo install` and no prior `just validate`
are required before `just run`.

`just run` keeps VCP’s custom TLS 1.3 serve path. `topcoat dev` / `just
dev` is for UI HMR only; it does not replace HTTPS. Production fails
closed if the asset bundle is missing (`AssetBundle::load()`). Pass
`--release` through `just run` / `just bundle` so binary and asset IDs
stay matched (a profile mismatch panics at request time).

Smoke against a self-signed cert:

```bash
curl -k https://127.0.0.1:3000/login
```

Browsers will warn on the self-signed cert until you trust it or use ACME in staging.

### Seed login

On first boot with an empty `users` table the app seeds:

| Email | Password | Notes |
|-------|----------|--------|
| `support@vauban.sh` | `password` | Vauban Support (`portal_role=admin`); membership on reserved org `vauban`; lands on `/vauban` |
| `l.martin@acme.example` | `password` | Client user (`role:org`) on `acme-infrastructure` only (org technical contact) |

Slug **`vauban`** is reserved (not a billable client). Client companies cannot create or rename to that slug.

## Route map

| Path | Surface |
|------|---------|
| `/login` | Sign in |
| `/{org}` | Dashboard (clients + staff preview on `vauban`) |
| `/{org}/docs` | Documentation KB (shared catalogue) |
| `/{org}/builds` | Builds (GA + that org's private releases) |
| `/{org}/issues` | Client issue tracker (**not** for slug `vauban`) |
| `/{org}/account` | Account & subscription |
| `/admin` | Admin hub (redirects to `/admin/issues`) |
| `/admin/issues` | Aggregated issues (staff; optional org filter) |
| `/admin/docs` | Documentation editor |
| `/admin/releases` | Release manager (GA or org-targeted) |
| `/admin/companies` | Client companies (excludes reserved `vauban`) |

Wrong org slug → **404** (no cross-tenant leak). `/admin/*` requires Vauban Support (`portal_role=admin` + Casbin `admin:view`). Direct `/vauban/issues*` redirects to `/admin/issues`.

## Validate

```bash
just validate         # ensure-vcp-test + fmt-check + clippy + bundle + tests
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
bash scripts/check_builds_entitlement.sh
bash scripts/check_toasty_filters.sh
bash scripts/check_docs_search_shard.sh
bash scripts/check_display_tz.sh
```

Staging smoke runbooks live under [`docs/runbooks/`](docs/runbooks/).
After model/schema changes, reset the test DB: `just db-reset-test`.
