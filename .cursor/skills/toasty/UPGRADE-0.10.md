# Toasty 0.9 → 0.10 (VCP playbook)

Upstream release:
[toasty-v0.10.0](https://github.com/tokio-rs/toasty/releases/tag/toasty-v0.10.0)
(2026-08-12). Re-clone `tokio-rs/toasty` at tag `toasty-v0.10.0`
when a bump needs the upstream tree.

**Status:** VCP pins **0.10.0** (`Cargo.toml` / lock). Hybrid
`embed_migrations!`, cursor scans (`.paginate` / `advance_scan_page`),
unique lookups, and `upsert_by_*` are in tree. Numbered SSR lists stay
on `.limit()` / `.offset()` / `.count()`.

## What 0.10 actually is

Application model/query code VCP already writes is **source-compatible**.
The release is mostly: embed migrations, more reliable cursor
pagination, `net` types, richer embeds, wasm for core crates, MySQL
driver TLS rewrite, two low-level breaking changes.

### Highlights (use these)

**1. Embedded migrations** (`#1095`)

```rust
static MIGRATIONS: toasty::migration::MigrationSet =
    toasty::embed_migrations!(); // default: CARGO_MANIFEST_DIR/toasty/

let report = MIGRATIONS.apply(&db).await?;
// report.applied() / report.skipped()
```

- Compile-time: parse `history.toml` (version 1), unique ids/names,
  each `migrations/{name}` exists → `include_str!`.
- Snapshots are **not** embedded (generate-only).
- Runtime: `db.connection()` (pool), skip ids already in
  `__toasty_migrations`, apply pending in history order, stop on first
  error.
- Override path: `embed_migrations!("toasty")` relative to the crate
  that **invokes** the macro (VCP binary crate root).
- **Does not replace** `vcp migration generate`. Dev still writes SQL
  on disk; rebuild re-embeds.
- **Interop with CLI:** same table, same ids. Hybrid is safe if SQL
  for an id never diverges after apply.

VCP today (`src/db.rs`): filesystem loop via
`Config::package_root()` + `db.driver().connect()`. 0.10 embed uses
`CARGO_MANIFEST_DIR` at compile and `Db::connection()` at apply —
document that gap if both stay.

**Exploit for VCP:** `static MIGRATIONS` in `db::connect` so prod boot
does not depend on `/usr/local/share/vcp/toasty` being present.
Keep `vcp migration apply` in `+POST_INSTALL` (idempotent). Do **not**
drop filesystem apply until embed is proven (pkg + `just run`).

**2. Cursor pagination** (fixes `#1124` `#1142` `#1152` `#1153`)

```rust
let page = Issue::all()
    .filter(...)
    .order_by(Issue::fields().updated_at().desc())
    .paginate(LIST_PAGE_SIZE)
    .exec(&mut db)
    .await?;
// page.items, page.next_cursor, page.prev_cursor
// page.next(&mut db).await? / page.prev(...)
```

- Requires `.order_by()`. Engine appends PK when order is not unique.
- Compound cursors are lexicographic; PG NULLs last on ASC.
- `.include()` preserves cursors.
- First page: `prev_cursor` is `None`.
- `per_page` is an **upper bound**. End-of-list = `!page.has_next()`,
  not `len < per_page`.

**Keep for VCP SSR:** `.limit().offset()` + `.count()` + `?page=N`
(`list_page.rs`). Numbered pagers do not map to opaque cursors.

**Exploit:** batch/export/drain loops (issue notify leftovers, docs
bundle, seed resync) — `.paginate(n)` + `while let Some(p) = page.next()`.

**Panics (do not mix):** `.paginate()` after `.limit()`; `.offset()`
after `.paginate()`; `.offset()` without `.limit()` (already 0.9).

**3. Feature `net`** (`#1178`)

`toasty::stmt::{IpCidr, IpInet, MacAddr6, MacAddr8}` → PG `CIDR` /
`INET` / `MACADDR` / `MACADDR8`. Enable only if a model needs it.

**4. Embeds** (`#1170` `#1180`)

Newtype embeds: `.ne/.gt/…` and `.asc()/.desc()` without `._0()`.
`#[belongs_to]` inside `#[derive(Embed)]` requires `Deferred<T>` and
explicit key fields; **no** `.include()` on those relations.

VCP models are flat FKs — no change required.

### Upgrade notes that do **not** apply to VCP

| Note | Why ignore |
|------|------------|
| MySQL URL `require_ssl` → `ssl-mode=verify_identity`; rustls default | VCP is PostgreSQL only |
| `Capability::sql` is now `Option<Dialect>`; use `.sql()` for bool | VCP never reads `Capability` |
| Removed unused schema/statement helpers (`#1149`) | Generated `Model` / `create!` / `Query` unchanged |

## Already in 0.9 — adopt on the same bump if useful

| API | When to use in VCP |
|-----|--------------------|
| `Model::upsert_by_*` | Idempotent writes: outbox-ish rows, storage mirrors, seed upserts (`or_ignore` / `on_create` / `on_update` + `increment()`). PG supported; MySQL rejected upstream. |
| `.include(rel.filter(...).order_by(...))` | Preload a slice of children (not just `DocArticle.body`). |
| `#[document]` / `Json<T>` / `#[column(type = jsonb)]` | Queryable JSON vs opaque blob. Prefer `#[document]` when the shape is known. |

Do not invent a second SQL path for these.

## Cargo bump

```toml
toasty = { version = "0.10.0", features = ["postgresql", "migration"] }
toasty-cli = "0.10.0"
```

0.10 crate `default` is `["rustls"]` (MySQL TLS forwarding). Optional:
`default-features = false` if you want a slimmer graph; PG TLS stays
on `toasty-driver-postgresql`.

Pin **both** facade and CLI. Re-run `just db-migrate` only if generate
changed; existing `toasty/history.toml` + SQL apply as-is.

## VCP file map (expect compile-clean)

| Surface | Path | 0.10 action |
|---------|------|-------------|
| Pin | `Cargo.toml` / lock | Bump |
| Connect + apply | `src/db.rs` | Optional: replace filesystem loop with `MIGRATIONS.apply(&db)` |
| CLI | `src/main.rs` `run_migration` | Keep `ToastyCli` |
| Pkg | `pkg/+POST_INSTALL` | Keep `vcp migration apply`; embed makes it a no-op skip |
| Models | `src/models/mod.rs` | No attr rewrite |
| Lists | `src/app/org/issues.rs`, docs, releases, shards | Keep offset+count |
| OCC / tx | `src/issue_status.rs` | No change; engine tx rollback (0.9) already helps |
| Deferred body | `src/app/admin/docs/doc.rs` | `.include(body)` still valid |
| Lints | `scripts/check_toasty_migrations.sh` | If embed: pin `embed_migrations!` + still pin `apply_pending` or successor |

## Engine fixes you get for free

- `#1138` IN-subquery optimization (`in_list`, relation filters).
- `#1148` Null FKs excluded from relation subqueries.
- `#1151` `.offset(n).first()` / `.one()` keep the offset.
- `#1124` `#1142` `#1152` `#1153` cursor pagination correctness.

## Suggested migration sequence

1. Bump crates; `just fmt` + clippy `-D warnings` + `just test` (full
   pyramid filters that touch DB: `toasty_migrations`, `portal_issues`,
   `admin_docs`, `builds_entitlement`, `issue_notify`, …).
2. Decide apply strategy: **A** filesystem only (status quo), **B**
   embed in `db::connect`, **C** hybrid B + CLI. Prefer **C**.
3. Do **not** rewrite `list_page` / `?page=` to cursors in the same PR.
4. Optionally: one `upsert_by_*` on a hot idempotent write (prove API).
5. Optionally: one job uses `.paginate()` instead of offset loops.
6. Update this skill’s pin sentence once `Cargo.toml` says 0.10.
7. Staging: `vcp migration apply` then boot; confirm
   `__toasty_migrations` rows; pkg upgrade must **not** drop `vcp`.

## Anti-patterns on the bump

| Forbidden | Why |
|-----------|-----|
| Call `embed_migrations!` while still on 0.9 | Macro does not exist |
| Rewrite every list to `.paginate()` | Breaks numbered pager + `.count()` UX |
| Change SQL of an already-applied id | Both CLI and embed skip by id |
| `push_schema` in prod | Unchanged invariant |
| Enable `net` “just in case” | Unused driver types |
| Treat MySQL TLS notes as PG work | Wrong backend |

## Upstream files (study)

| Topic | Path in a `toasty-v0.10.0` checkout |
|-------|-----------------------------------------------|
| Embed macro | `crates/toasty-macros/src/embed_migrations.rs` |
| `MigrationSet` | `crates/toasty/src/migration/embed.rs` |
| Guide migrations | `docs/guide/src/schema-management.md` |
| Paginate / Page | `crates/toasty/src/stmt/{paginate,page}.rs` |
| Guide sort/page | `docs/guide/src/sorting-limits-and-pagination.md` |
| PK tie-break | `crates/toasty/src/engine/normalize/paginate.rs` |
| Examples | `examples/product-search`, `examples/service-ops`, `examples/store-operations` |
| Changelog | `crates/toasty/CHANGELOG.md` |

## Related

- Query invariants: [SKILL.md](SKILL.md)
- Prod migrate without wiping DB: `pkg/+POST_INSTALL`,
  `docs/runbooks/toasty_migrations_smoke_test.md`
