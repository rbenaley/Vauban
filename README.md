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
just run          # build + asset bundle + HTTPS on https://127.0.0.1:3000
just validate     # fmt-check (rustfmt + topcoat fmt) + clippy + tests
just dev          # topcoat HMR (no custom TLS); prefer just run for HTTPS
just bundle       # cargo build + topcoat asset bundle → target/assets
just fmt          # cargo fmt + topcoat fmt
```

`just run` and `just validate` install the pinned Topcoat CLI
(`topcoat-cli` 0.4.0) on first use when `topcoat` is missing from
`PATH` / `$CARGO_HOME/bin`. No prior `just validate` is required before
`just run`. Manual install remains available:

```bash
cargo install topcoat-cli --version 0.4.0
```

`just run` keeps VCP’s custom TLS 1.3 serve path. `topcoat dev` is for
UI HMR only; it does not replace HTTPS. Production fails closed if the
asset bundle is missing (`AssetBundle::load()`).

Smoke against a self-signed cert:

```bash
curl -k https://127.0.0.1:3000/login
```

Browsers will warn on the self-signed cert until you trust it or use ACME in staging.

### Seed login

On first boot with an empty `users` table the app seeds:

| Field | Value |
|-------|--------|
| Email | `admin@acme.example` |
| Password | `password` |
| Org slug | `acme-infrastructure` |
| Role | `admin` |

A second user `l.martin@acme.example` / `password` is seeded as `member` (no admin rail).

## Route map

| Path | Surface |
|------|---------|
| `/login` | Sign in |
| `/{org}` | Dashboard |
| `/{org}/docs` | Documentation KB |
| `/{org}/builds` | Certified builds |
| `/{org}/issues` | Issue tracker |
| `/{org}/account` | Account & subscription |
| `/{org}/admin/docs` | Documentation editor |
| `/{org}/admin/releases` | Release manager |
| `/{org}/admin/companies` | Client companies |

Wrong org slug → **404** (no cross-tenant leak). Admin nest requires `admin:view`.

## Validate

```bash
just validate         # ensure-vcp-test + fmt-check + clippy + bundle + tests
```

Structural lints (also exercised via `*_invariants_test`):

```bash
bash scripts/check_auth_tenant.sh
bash scripts/check_http_edge.sh
bash scripts/check_portal_shell.sh
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
