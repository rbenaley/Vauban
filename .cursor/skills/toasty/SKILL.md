---
name: toasty
description: >-
  Toasty ORM conventions for VCP (PostgreSQL): query API (filter,
  limit/offset, count, order_by, ilike, in_list, or), migrations, and
  anti-patterns against full-table loads. Use when writing or reviewing
  models, queries, list/search loaders, shards, seats, entitlement SQL,
  or Toasty migrations — whenever tempted to Model::all() + Rust
  filter/sort/page — and when planning or executing a Toasty 0.9 to
  0.10 upgrade (embed_migrations, cursor pagination, net types).
---

# Toasty + PostgreSQL (VCP)

Durable ORM knowledge for this portal. Product wiring (`db(cx)`,
tenancy, escape hatch) also lives in `web-stack`; this skill is the
**query and schema** source of truth.

Upstream: [tokio-rs/toasty](https://github.com/tokio-rs/toasty) ·
[guide](https://tokio-rs.github.io/toasty/nightly/guide/) ·
filter guide: `docs/guide/src/filtering-with-expressions.md`.

**Confirm the pin in `Cargo.toml` before writing APIs.** As of this
skill refresh, VCP still ships **`toasty = "0.9.0"`** (`postgresql` +
`migration`). Do **not** call 0.10-only APIs (`embed_migrations!`,
`.paginate()`, `toasty::stmt::IpCidr`) until the crate is bumped.

0.10 upgrade playbook: [UPGRADE-0.10.md](UPGRADE-0.10.md).
Re-clone tag `toasty-v0.10.0` from `tokio-rs/toasty` only when a bump
needs the upstream tree.

## Non-negotiable (architecture audit)

VCP historically loaded full tables (`Model::all().exec()`), then
filtered / sorted / paginated in Rust. **That is application debt, not
an ORM limit.** Toasty 0.9 already exposes SQL-side tooling. New and
refactored loaders MUST push work into the query. 0.10 does not change
this rule.

| Forbidden (default) | Required instead |
|---------------------|------------------|
| `Model::all().exec()` then Rust `.filter` / `.sort` / `page_slice` for product lists | `.filter(...)` + `.order_by(...)` + `.limit(n).offset(m)` |
| Tenant / entitlement only in Rust after loading every row | SQL predicate (`eq` / `in_list` / `.or`) so other tenants never enter the process |
| `User::all()` / `Organization::all()` to resolve a few display names | `.filter(id.in_list(page_ids))` after the page set is known |
| `rows.len()` after loading memberships for a count | `.count()` → `COUNT(*)` |
| Substring search via Rust `str::contains` on full scans | Postgres `.ilike("%…%")` (or `.like` / `.starts_with`) |
| Inventing `sqlx` because “Toasty cannot page” | Toasty query API first; `sqlx` only as a documented last resort (`web-stack`) |

Security note (audit §3.1): org builds that load `Release::all()` then
filter in Rust have **no DB-side tenant net**. Prefer
`organization_id.in_list([GA, org_id])` or `.eq(GA).or(.eq(org_id))`
in SQL. Casbin alone is never enough.

`page_slice` in `src/list_page.rs` remains valid for pure in-memory
slices. It is **not** a substitute for SQL pagination on Postgres lists.

### Release semver order (SQL)

`Release` stores materialized sort columns from
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
    Release::fields().is_industrial().desc(),
    Release::fields().has_client_suffix().desc(),
    Release::fields().client_suffix().asc(),
    // Admin list only — PUBLISHED before HIDDEN:
    // Release::fields().status().desc(),
))
.limit(PAGE)
.offset(page_offset(page, PAGE))
```

Do **not** `cmp_version_desc` / `page_slice` on those list hot paths.

## Query shape (typed)

`Query<T>`’s type parameter is the **returning** shape:

| Type | `exec` yields | Typical constructor |
|------|---------------|---------------------|
| `Query<List<M>>` | `Vec<M>` | `M::all()`, `M::filter(...)` |
| `Query<M>` | `M` (error if missing) | `.one()` |
| `Query<Option<M>>` | `Option<M>` | `.first()` |
| `Query<u64>` | count | `.count()` on a list query |

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

### `limit` / `offset` caveats

- `.limit(n)` is an **upper bound**, not a hard guarantee.
- `.offset(n)` **requires** a prior `.limit(...)` — otherwise it
  **panics** (`limit required for offset`).
- Do not mix offset with cursor-based limits (0.10 `.paginate()`).

### Filters (field paths)

| Need | API | Notes |
|------|-----|-------|
| Equality / compare | `.eq` `.ne` `.gt` `.ge` `.lt` `.le` | Indexed `filter_by_*` for simple equals |
| Membership | `.in_list([...])` | Multi-id lookups, entitlement sets |
| Combine | `.and` / `.or` / `.not()` | Tenant OR GA releases |
| Null (`Option`) | `.is_none()` / `.is_some()` | |
| Prefix | `.starts_with(prefix)` | Case-sensitive |
| Pattern (PG) | `.like` / `.ilike` | Caller supplies `%` / `_` |
| Escaped wildcards | `.like_with_escape` / `.ilike_with_escape` | Untrusted search |
| Array element | `.contains(value)` on `Vec` scalars | **not** substring on `String` |
| HasMany | path `.any(child_filter)` / `.all(...)` | Exists / forall |

**Substring on `String`:** `.ilike(format!("%{needle}%"))` with escape
when untrusted. Do **not** call `.contains` on a string path.

### Personalization for VCP listings

1. Resolve auth + tenant (`require_org` / `require_staff` + Casbin).
2. Push **tenant / entitlement** into `.filter` (fail closed).
3. Push **search** into `.ilike` / `.or`.
4. `.order_by(field.asc()|.desc())` (tuples for tie-breakers).
5. `.count()` for pager totals; `.limit(PAGE).offset((page-1)*PAGE)`
   for SSR `?page=N`.
6. Resolve display names with `.filter(User::fields().id().in_list(ids))`
   for ids on **that page only**.

## Mutations and load helpers

- Create: `toasty::create!(Model { … }).exec(&mut db).await?`
- Prefer generated `get_by_*` / `filter_by_*` for unique / indexed keys.
- Updates: instance `.update()` / `toasty::update!`.
- OCC: `#[version]` on `Issue` / `IssueMailOutbox`.
- Deferred: `Deferred<T>` + `.include(Model::fields().body())` on detail
  views (not `#[deferred]` — removed since 0.7).
- Projections: `.select(...)` when a full model is unnecessary.
- 0.9 already has `upsert_by_*` (VCP underuses it — see upgrade note).

## Migrations (VCP today — 0.9 filesystem)

- Models under `src/models/`; schema via `toasty/` + `vcp migration`.
- Flow: edit models → `just db-migrate-generate NAME=…` → **review SQL**
  → `just db-migrate`.
- `db::connect` → `apply_pending_migrations` reads
  `Config::package_root()` (`VCP_PACKAGE_ROOT` / parent of
  `VCP_CONFIG_DIR` / `/usr/local/share/vcp`) — **not**
  `CARGO_MANIFEST_DIR`.
- Do **not** use `push_schema` for the app DB.
- Prod pkg: `+POST_INSTALL` runs `VCP_ENVIRONMENT=production vcp
  migration apply` (does **not** drop the database).
- Tests: `vcp_test` (`just db-create-test` / `just db-reset-test`).

## 0.10 — ready, not yet pinned

Release: [toasty-v0.10.0](https://github.com/tokio-rs/toasty/releases/tag/toasty-v0.10.0)
(2026-08-12). Model/query APIs VCP uses are **source-compatible**.
Breaking changes hit custom drivers / `Capability::sql` (VCP unused)
and **MySQL TLS** (VCP unused).

**Exploit on bump (do not invent 0.9 workarounds):**

| 0.10 addition | VCP use |
|---------------|---------|
| `embed_migrations!` + `MigrationSet::apply` | Compile `toasty/history.toml` + SQL into `vcp`; apply via `Db` pool. Complements (does not replace) `vcp migration generate`. Good for boot without shipping `share/vcp/toasty` **or** hybrid: embed at `db::connect`, keep CLI for ops. Same `__toasty_migrations` ids. |
| Deterministic `.paginate(n)` / `Page` | Jobs, exports, “load more”. **Keep** `.limit().offset()` + `.count()` for numbered `?page=N` SSR (`list_page.rs`). Do not mix `.paginate()` with `.limit()` / `.offset()` (panic). |
| Feature `net` | Native PG `CIDR`/`INET`/`MACADDR` — only if a model needs it. |
| Engine fixes | Free: IN-subquery, null FK exclusion, offset+`.first()`, multi-key / include cursors. |

**Already in 0.9 (adopt anytime):** `upsert_by_*`, filtered/ordered
`.include()`, `#[document]` / JSONB. See [UPGRADE-0.10.md](UPGRADE-0.10.md).

When bumping: follow that file’s checklist; keep this skill’s query
invariants; re-pin `toasty` + `toasty-cli` together.

## When unsure

1. Read this skill + `Cargo.toml` pin.
2. If the pin is still 0.9, write 0.9 APIs. If migrating, read
   [UPGRADE-0.10.md](UPGRADE-0.10.md) and the tagged tree
   re-clone tag `toasty-v0.10.0` from `tokio-rs/toasty`.
3. Prefer the **tagged** guide over guessing from `main`.

## Related

- `web-stack` — `db(cx)`, pin policy, escape hatch, list page sizes
- `quality-assurance` / `vcp-test-pyramid.mdc` — DB tests on Postgres
- `portal-security.mdc` / `casbin-permissions.mdc` — tenant + capability
- Architecture: `.cursor/audits/vcp_architecture_toasty_query_debt_2026-08-02.md`
