# Runbook -- Minimal boot seed vs `vcp seed-data`

> Manual validation after changing **empty-DB boot seed** or the
> **`vcp seed-data`** CLI. CI covers unit / invariants / proptest / battle /
> E2E against `vcp_test`; staging proves a real reset + HTTPS boot.
>
> Audience: release / staging operators.
> Severity: **BLOCKING** for seed / demo-catalog changes.

Related:

- [README](../../README.md) (login + seed blurb)
- Lint: `scripts/check_seed_data.sh`
- Filter: `cargo test --test integration_tests -- seed_data -- --test-threads=1`
- Migrations: [`toasty_migrations_smoke_test.md`](toasty_migrations_smoke_test.md)

## Automated prerequisites

```bash
bash scripts/setup_test_db.sh   # or: just db-create-test
bash scripts/check_seed_data.sh
rtk cargo clippy --all-targets -- -D warnings
rtk cargo test --test integration_tests -- seed_data -- --test-threads=1
rtk cargo test --lib cli:: -- --test-threads=1
```

## Lab prerequisites

- Postgres `vcp` (dev) and willingness to `just db-reset`.
- `VCP_ENVIRONMENT=development`.
- Optional: delete local `vcp-storage` blob root if testing empty Builds UX.

## A -- Minimal boot after reset

```bash
just db-reset
just db-create
just run
```

Then open `/login`, magic-link as `l.martin@acme.example`, browse docs and builds.

| Check | Pass | Fail |
|-------|------|------|
| Docs | Exactly **Quick start** published | Extra demo KB articles without `seed-data` |
| Builds | **Empty** (no GA rows) | 23+ GA versions present after bare boot |
| Issues | **Empty** list | `VBN-214` / `VBN-208` present without `seed-data` |
| Tenants | `acme-infrastructure` + reserved `vauban` | Missing demo login org |

## B -- Full demo catalog via CLI

With the portal stopped (or a second shell):

```bash
just seed-data
# help: cargo run -- --help
```

| Check | Pass | Fail |
|-------|------|------|
| Docs | **7** published articles | Still only Quick start |
| Builds | **24** releases (23 GA + `v0.8.6-acme1`) | Missing GA or Acme private |
| Issues | **2** sample issues (+ comments on VBN-214) | Zero issues |
| CLI help | `vcp --help` prints `seed-data` usage, exit 0 | Missing command / non-zero |

**Idempotent:** running `seed-data` twice must not panic; counts stay stable.

## C -- Unknown command

```bash
cargo run -- not-a-command
```

**Pass:** non-zero exit, usage on stderr/stdout mentioning `seed-data`.
