# Runbook -- Toasty cursor pagination (jobs)

> Manual check after changing full-table scans (`resync`, docs export,
> seed comment backfill, magic-link purge, org image delete). Numbered
> SSR lists (`?page=N`) stay on `.limit()` / `.offset()` / `.count()`.
>
> Audience: release / staging operators.
> Severity: **Medium** (data jobs; not auth).

Related:

- Helper: `src/toasty_page.rs`
- Lint: `scripts/check_toasty_paginate.sh`
- Filter: `cargo test --test integration_tests -- toasty_paginate -- --test-threads=1`
- Docs export: [docs_bundle_smoke_test.md](docs_bundle_smoke_test.md)
- Seed: [seed_data_smoke_test.md](seed_data_smoke_test.md)

## Automated prerequisites

```bash
bash scripts/setup_test_db.sh
bash scripts/check_toasty_paginate.sh
rtk cargo clippy --all-targets -- -D warnings
rtk cargo test --test integration_tests -- toasty_paginate -- --test-threads=1
```

## A -- Export after seed

```bash
just seed-data
mkdir -p /tmp/vcp-docs-paginate
rm -rf /tmp/vcp-docs-paginate/*
vcp docs export /tmp/vcp-docs-paginate
```

**Pass:** file count equals `DocArticle` rows; no panic; empty extra pages
are not required (end of list is no next cursor).

**Fail:** export loads the table without `.paginate(` / helper, or skips
rows when the catalog is larger than `SCAN_PAGE_SIZE`.

## B -- Resync + seed idempotent

```bash
just seed-data
just seed-data
```

**Pass:** second seed does not duplicate issues/docs/releases; portal
boots after `db::connect` (resync walks releases in pages).
