---
name: toasty
description: >-
  Toasty 0.9 ORM conventions for VCP (PostgreSQL): query API (filter,
  limit/offset, count, order_by, ilike, in_list, or), migrations, and
  anti-patterns against full-table loads. Use when writing or reviewing
  models, queries, list/search loaders, shards, seats, entitlement SQL,
  or Toasty migrations — and whenever tempted to Model::all() + Rust
  filter/sort/page.
---

# Toasty (VCP pin 0.9) + PostgreSQL

Durable ORM knowledge for this portal. Product wiring (`db(cx)`,
tenancy, escape hatch) also lives in `web-stack`; this skill is the
**query and schema** source of truth.

Upstream: [tokio-rs/toasty](https://github.com/tokio-rs/toasty) ·
[guide](https://tokio-rs.github.io/toasty/nightly/guide/) ·
filter guide: `docs/guide/src/filtering-with-expressions.md` in the
upstream tree. Confirm names against the locked crate in `Cargo.toml`
(`toasty = "0.9.0"`, features `postgresql` + `migration`).

## Non-negotiable (architecture audit)

VCP historically loaded full tables (`Model::all().exec()`), then
filtered / sorted / paginated in Rust. **That is application debt, not
an ORM limit.** Toasty 0.9 already exposes SQL-side tooling for those
jobs. New and refactored loaders MUST push work into the query.

| Forbidden (default) | Required instead |
|---------------------|------------------|
| `Model::all().exec()` then Rust `.filter` / `.sort` / `page_slice` for product lists | `.filter(...)` + `.order_by(...)` + `.limit(n).offset(m)` |
| Tenant / entitlement only in Rust after loading every row | SQL predicate (`eq` / `in_list` / `.or`) so other tenants never enter the process |
| `User::all()` / `Organization::all()` to resolve a few display names | `.filter(id.in_list(page_ids))` (or indexed getters) after the page set is known |
| `rows.len()` after loading memberships for a count | `.count()` → `COUNT(*)` |
| Substring search via Rust `str::contains` on full scans | Postgres `.ilike("%…%")` (or `.like` / `.starts_with`) on the query |
| Inventing `sqlx` because “Toasty cannot page” | Use Toasty query API first; `sqlx` only as a documented last resort (`web-stack`) |

Security note (audit §3.1): org builds that load `Release::all()` then
filter in Rust have **no DB-side tenant net**. Prefer
`organization_id.in_list([GA, org_id])` or `.eq(GA).or(.eq(org_id))`
(and any channel predicates) in SQL. Casbin alone is never enough.

`page_slice` in `src/list_page.rs` remains valid for pure in-memory
slices (tests, tiny fixed vecs). It is **not** a substitute for SQL
pagination on Postgres-backed listings.

### Release semver order (SQL)

`Release` stores materialized sort columns written from
`release_pkg::version_sort_fields(version)` on every create/update
(and `db::resync_release_sort_keys` after migrations):

`v_major`, `v_minor`, `v_patch`, `has_client_suffix` (`0`/`1`),
`client_suffix`.

Org Builds and `/admin/releases` MUST order with a Toasty tuple and page
in SQL:

```rust
.order_by((
    Release::fields().v_major().desc(),
    Release::fields().v_minor().desc(),
    Release::fields().v_patch().desc(),
    Release::fields().has_client_suffix().desc(),
    Release::fields().client_suffix().asc(),
))
.limit(PAGE)
.offset(page_offset(page, PAGE))
```

Do **not** `cmp_version_desc` / `page_slice` on those list hot paths.
`cmp_version_desc` remains the pure-order contract for unit/proptest.

## Query shape (typed)

`Query<T>`’s type parameter is the **returning** shape:

| Type | `exec` yields | Typical constructor |
|------|---------------|---------------------|
| `Query<List<M>>` | `Vec<M>` | `M::all()`, `M::filter(...)` |
| `Query<M>` | `M` (error if missing) | `.one()` |
| `Query<Option<M>>` | `Option<M>` | `.first()` |
| `Query<u64>` | count | `.count()` on a list query |

Chain on the model helpers (preferred) or `Query::<List<M>>::all()`:

```rust
let page = Issue::all()
    .filter(Issue::fields().organization_id().eq(org_id))
    .filter(Issue::fields().title().ilike(format!("%{q}%")))
    .order_by(Issue::fields().updated_at().desc())
    .limit(LIST_PAGE_SIZE)
    .offset((page.saturating_sub(1)) * LIST_PAGE_SIZE)
    .exec(&mut db)
    .await?;

let total = Issue::all()
    .filter(Issue::fields().organization_id().eq(org_id))
    .count()
    .exec(&mut db)
    .await?;
```

### `limit` / `offset` caveats (upstream docs)

- `.limit(n)` is an **upper bound**, not a hard guarantee: Toasty may
  apply extra post-DB filtering, so the `Vec` can be shorter than `n`.
- `.offset(n)` **requires** a prior `.limit(...)` on the same query —
  otherwise it **panics** (`limit required for offset`).
- Do not mix offset with cursor-based limits.

### Filters (field paths)

Build `Expr<bool>` via `Model::fields().…` then `.filter(expr)`.

| Need | API | Notes |
|------|-----|-------|
| Equality / compare | `.eq` `.ne` `.gt` `.ge` `.lt` `.le` | Indexed `filter_by_*` for simple equals |
| Membership | `.in_list([...])` | Multi-id lookups, entitlement sets |
| Combine | `.and(expr)` / `.or(expr)` / `.not()` | Tenant OR GA releases, etc. |
| Null (`Option`) | `.is_none()` / `.is_some()` | |
| Prefix | `.starts_with(prefix)` | Case-sensitive; OK across backends |
| Pattern (case-sensitive PG) | `.like(pattern)` | Caller supplies `%` / `_` wildcards |
| Pattern (case-insensitive PG) | `.ilike(pattern)` | **PostgreSQL only** (VCP default) |
| Escaped wildcards | `.like_with_escape` / `.ilike_with_escape` | Literal `%` / `_` in user input |
| Array element | `.contains(value)` on `Vec` scalar fields | `= ANY(col)` — **not** substring on `String` |
| Array set ops | `.intersects` / `.is_superset` / `.len` | Postgres array ops |
| HasMany | path `.any(child_filter)` / `.all(...)` | Exists / forall via subquery |

**Substring search on `String`:** use `.ilike(format!("%{needle}%"))`
(escape `%`/`_` from untrusted input with `ilike_with_escape` when
needed). Do **not** call `.contains` on a string path — that API is for
`Vec` scalars.

### Personalization for VCP listings

1. Resolve auth + tenant (`require_org` / `require_staff` + Casbin).
2. Push **tenant / entitlement** into `.filter` (fail closed).
3. Push **search** into `.ilike` / `.or` of field predicates.
4. `.order_by(field.asc()|.desc())` (tuples for tie-breakers).
5. `.count()` for pager totals; `.limit(PAGE).offset((page-1)*PAGE)`
   for the page rows.
6. Resolve display names with `.filter(User::fields().id().in_list(ids))`
   for ids on **that page only**.

Seed / one-shot admin tools may still scan; document why. Hot paths
(pages, shards, procedures) must not.

## Mutations and load helpers

- Create: `toasty::create!(Model { … }).exec(&mut db).await?`
- Prefer generated `get_by_*` / `filter_by_*` for unique / indexed keys.
- Updates: model update builders / `toasty::update!` per upstream guide.
- Deferred large columns: `#[deferred]` + `.include(Model::fields().body())`
  on detail views; omit on index queries.
- Projections: `.select(Model::fields().title())` (or tuples) when a full
  model is unnecessary.

## Migrations (VCP)

- Models under `src/models/`; schema via `toasty/` + `vcp migration`.
- Flow: edit models → `just db-migrate-generate NAME=…` → **review SQL**
  (interactive rename vs drop; preserve data) → `just db-migrate`.
- `db::connect` applies pending migrations. Do **not** use `push_schema`
  for the app DB.
- Non-TTY: `script -q /dev/null cargo run --bin vcp -- migration generate --name …`
  then answer rename prompts carefully (prefer RENAME over DROP).
- Tests: `vcp_test` (`just db-create-test` / `just db-reset-test`).

## When unsure

1. Read this skill + `Cargo.toml` pin.
2. Open upstream guide
   ([filtering](https://tokio-rs.github.io/toasty/nightly/guide/filtering-with-expressions.html)
   or clone `tokio-rs/toasty` and read `crates/toasty/src/stmt/{query,path,expr}.rs`).
3. Prefer a shallow clone of the **tagged / crates.io 0.9.0** tree over
   guessing from memory or from a newer `main`.

## Related

- `web-stack` — `db(cx)`, pin policy, escape hatch, list page sizes
- `quality-assurance` / `vcp-test-pyramid.mdc` — DB tests on Postgres
- `portal-security.mdc` / `casbin-permissions.mdc` — tenant + capability
- Architecture findings: `.cursor/audits/vcp_architecture_toasty_query_debt_2026-08-02.md`
