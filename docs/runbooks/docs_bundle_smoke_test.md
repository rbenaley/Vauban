# Runbook -- Docs Markdown bundle export/import

> Ops CLI to move `DocArticle` rows between VCP instances as a directory of
> Markdown files with YAML frontmatter. No browser editing.
>
> Audience: operators migrating KB content between staging/prod labs.
> Severity: **Medium** (content mobility; not auth).

Related:

- CLI: `vcp docs export <DIR>` / `vcp docs import <DIR>`
- Just: `just docs-export DIR=…` / `just docs-import DIR=…`
- Lint: `scripts/check_docs_bundle.sh`
- Filter: `cargo test --test integration_tests -- docs_bundle -- --test-threads=1`

## Automated prerequisites

```bash
bash scripts/setup_test_db.sh
rtk cargo fmt --all -- --check
rtk cargo clippy --all-targets -- -D warnings
bash scripts/check_docs_bundle.sh
rtk cargo test --test integration_tests -- docs_bundle -- --test-threads=1
```

## Lab prerequisites

- Two VCP databases (or wipe docs on the target) with the same schema.
- `VCP_CONFIG_DIR` / `VCP_ENVIRONMENT` pointing at the instance under test.
- Source instance has published (and optionally draft) docs under `/admin/docs`.

## A -- Export

1. On instance A: `mkdir /tmp/vcp-docs-bundle` (must be empty/new).
2. `vcp docs export /tmp/vcp-docs-bundle`
3. Expect one `{slug}__{version}.md` per row; each file has `---` frontmatter
   (`title`, `slug`, `summary`, `category`, `status`, `version`) and the
   dialect body.

**Fail if:** non-empty directory accepted; files missing frontmatter; body
stripped of callouts / fences.

## B -- Import (additive upsert)

1. On instance B (empty docs or older copies): `vcp docs import /tmp/vcp-docs-bundle`
2. Open `/admin/docs` — titles/slugs/statuses match the bundle.
3. Client `/{org}/docs/{slug}` shows published content.
4. Re-run import — counts show `updated=` (idempotent), not duplicate rows for
   the same `(slug, version)`.

**Fail if:** two PUBLISHED rows share a slug after import; unknown category is
silently accepted; import continues after a bad file (must fail-fast).

## C -- Version exclusivity

1. Bundle contains `slug__v1.md` PUBLISHED and `slug__v2.md` DRAFT (or the
   reverse order on disk).
2. After import, at most one PUBLISHED row exists for that slug.

Pass: staging A→B transfer without hand-editing Markdown.

## Out of scope

- ZIP as a first-class format (operators may `tar` the directory).
- Pruning target articles absent from the bundle.
- Admin UI upload/download.
