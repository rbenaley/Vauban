# Runbook -- Toasty migrations smoke test

> Manual validation after changing **models**, **`toasty/` migrations**, or
> `db::connect` schema application. CI covers unit / invariants / proptest /
> battle / E2E against `vcp_test`; staging proves migrate-on-boot against a
> durable Postgres.
>
> Audience: release / staging operators.
> Severity: **BLOCKING** for schema / ORM changes.

Related:

- Guide: [Toasty schema management](https://tokio-rs.github.io/toasty/nightly/guide/schema-management.html)
- Lint: `scripts/check_toasty_migrations.sh`
- CLI: `cargo run --bin vcp -- migration …` / `just db-migrate`
- Pin: Toasty **0.10.0** (`Cargo.toml` / `toasty-cli`; confirm with
  `scripts/check_toasty_migrations.sh`)

## Automated prerequisites

```bash
bash scripts/setup_test_db.sh
bash scripts/check_toasty_migrations.sh
rtk cargo clippy --all-targets -- -D warnings
rtk cargo test --test integration_tests -- toasty_migrations -- --test-threads=1
```

## Lab prerequisites

- Postgres with `vcp` (dev) and `vcp_test`.
- `VCP_ENVIRONMENT=development` for local `vcp migration` (defaults to
  development when unset; unlike `vcp` server which defaults to production).

## A -- Generate / apply locally

```bash
# After editing src/models:
just db-migrate-generate NAME=describe_change
# Review toasty/migrations/*.sql, then:
just db-migrate
just run
```

**Pass:** app boots; login works; no `column … does not exist` errors.

**Fail:** missing migration files, apply errors, or push_schema resurrected in
`src/db.rs`.

## B -- Fresh database

```bash
just db-reset
just run
```

**Pass:** demo login tenant exists (`l.martin@acme.example`); docs list shows
**Quick start** only (no GA builds until `just seed-data`).

Optional full demo catalog:

```bash
just seed-data
```

**Pass:** 7 docs, seeded GA + Acme-private releases, sample issues.

## C -- Staging

Apply pending migrations with the staging database URL (same `vcp
migration apply` with staging `VCP_ENVIRONMENT` / config), then smoke login
and one admin docs save.

**Pass:** `__toasty_migrations` contains the expected rows; app serves HTML.
Pkg upgrade must **not** drop database `vcp`.

## D -- Hybrid apply (embed + CLI)

`db::connect` applies **embedded** SQL (`embed_migrations!("toasty")`,
compile-time crate root). `vcp migration apply` / `+POST_INSTALL` still
reads `VCP_PACKAGE_ROOT` / `share/vcp/toasty` from disk. Both write the
same `__toasty_migrations` ids — do **not** change SQL for an already
applied id.

```bash
# After a pkg upgrade (filesystem CLI first):
VCP_ENVIRONMENT=production vcp migration apply
# Then boot: embed skips every recorded id.
just run
```

**Pass:** second apply (boot or CLI) is a no-op; `__toasty_migrations`
row count matches `toasty/history.toml`; database `vcp` is not dropped.

**Fail:** embed and CLI apply different SQL for the same id, or boot
fails because `share/vcp/toasty` is missing *and* the binary was built
without the matching history.
