---
name: Toasty 0.10 upgrade
overview: "Upgrade VCP from Toasty 0.9.0 to 0.10.0 in five sequential lots: pin bump, hybrid embedded migrations, cursor pagination on full scans, unique lookups on seed/CLI, then upsert_by_* on unique keys. Numbered SSR pagers stay on limit/offset/count. Each lot ships a full test pyramid."
todos:
  - id: lot1-pin
    content: "Lot 1: bump toasty + toasty-cli 0.10.0; cargo tree; existing pyramids green; skill/runbook pin"
    status: completed
  - id: lot2-embed
    content: "Lot 2: embed_migrations! hybrid apply; keep CLI + POST_INSTALL; extend toasty_migrations pyramid"
    status: completed
  - id: lot3-paginate
    content: "Lot 3: shared .paginate() helper on resync/export/refresh/demo-comment scans; toasty_paginate pyramid"
    status: completed
  - id: lot4-lookups
    content: "Lot 4: seed/CLI get_by_* / filter / .count(); shrink db.rs all() allowlist; extend seed_data pyramid"
    status: completed
  - id: lot5-upsert
    content: "Lot 5: upsert_by_* on StorageObject unique (scope, object_key); optional outbox; extend storage pyramid"
    status: completed
isProject: false
---

# Toasty 0.10 upgrade (five lots)

Follow [`.cursor/skills/toasty/UPGRADE-0.10.md`](.cursor/skills/toasty/UPGRADE-0.10.md). VCP still pins `toasty = "0.9.0"` in [`Cargo.toml`](Cargo.toml). Application query APIs are expected source-compatible; do **not** rewrite [`src/list_page.rs`](src/list_page.rs) or any `?page=N` SSR list (issues, docs, builds, releases, companies). Those stay `.limit()` / `.offset()` / `.count()`.

```mermaid
flowchart LR
  lot1[Lot1_pin]
  lot2[Lot2_embed]
  lot3[Lot3_paginate]
  lot4[Lot4_lookups]
  lot5[Lot5_upsert]
  lot1 --> lot2 --> lot3 --> lot4 --> lot5
```

**Out of scope (no schema invention):** feature `net` (no CIDR/INET/MAC columns), `#[document]` / JSONB, newtype `Embed` (models are flat FKs), MySQL TLS notes, changing SQL of an already-applied `toasty/history.toml` id, converting numbered pagers to cursors.

**Topcoat risk (Lot 1 first check):** `cargo tree -i toasty` after the bump. VCP owns `toasty::Db` via [`src/auth.rs`](src/auth.rs) `db(cx)` — Topcoat 0.5 must not force a second 0.9 graph on the same types. If it does, stop and report before embed/paginate work.

**After each lot:** `just fmt` + `fmt --check`, clippy `-D warnings`, matching `scripts/check_*.sh`, focused tests `--test-threads=1`. Do not start the next lot until the current pyramid is green. Commit only when the user asks (one commit per lot).

**Research notes (pre-implementation audit):** product list debt is already remediating (offset+count on SSR). Remaining work is bootstrap/seed, batch jobs, and manual upserts. No `.offset().first()` callers today (`#1151` is free). No JSON/`net` columns. `toasty_migrations` pyramid already exists (unit pins in [`src/db.rs`](src/db.rs) `mod tests`; invariants/proptest/battle/e2e under `tests/integration_tests/toasty_migrations_*`). Proptest today uses a **synthetic** `History`, not the real `toasty/history.toml`. `check_toasty_migrations.sh` does not pin the crate version yet. Dual apply path: pkg/`vcp migration apply` (filesystem + `VCP_PACKAGE_ROOT`) vs `db::connect` (Lot 2 must prove ids do not diverge).

---

## Lot 1 — Pin bump (compile-clean)

**Goal:** ship 0.10 with zero new APIs. Engine fixes (`#1138` IN-subquery, `#1148` null FKs, `#1151` offset+`.first()`, cursor correctness) come for free.

- Bump both: `toasty = { version = "0.10.0", features = ["postgresql", "migration"] }` and `toasty-cli = "0.10.0"`. Keep filesystem [`apply_pending_migrations`](src/db.rs) unchanged.
- Keep [`pkg/+POST_INSTALL`](pkg/+POST_INSTALL) `vcp migration apply`. Do not regenerate migrations unless generate output changed.
- Update pin sentences in [`.cursor/skills/toasty/SKILL.md`](.cursor/skills/toasty/SKILL.md), [`.cursor/skills/web-stack/SKILL.md`](.cursor/skills/web-stack/SKILL.md), and the Status line in `UPGRADE-0.10.md`.

**Pyramid (extend existing `toasty_migrations` + `toasty_filters`):**

- Unit: existing [`src/db.rs`](src/db.rs) `mod tests` + `seed_digest_tests` still compile (pins `apply_pending_migrations`, forbids `push_schema`).
- Invariants: pin `toasty = "0.10.0"` + `toasty-cli` in [`scripts/check_toasty_migrations.sh`](scripts/check_toasty_migrations.sh) / [`tests/integration_tests/toasty_migrations_invariants_test.rs`](tests/integration_tests/toasty_migrations_invariants_test.rs). Still forbid `push_schema`.
- Proptest / battle / E2E: re-run `toasty_migrations_*` and `toasty_filters_*` (already in tree).
- Smoke: add a 0.10 pin note to [`docs/runbooks/toasty_migrations_smoke_test.md`](docs/runbooks/toasty_migrations_smoke_test.md). Staging: boot + `__toasty_migrations` rows; pkg must not drop `vcp`.

Widen `just test` to DB surfaces that would catch a silent query break: `portal_issues`, `admin_docs`, `builds_entitlement`, `issue_notify`, `seed_data`, `docs_bundle`.

---

## Lot 2 — Hybrid `embed_migrations!` (strategy C)

**Goal:** boot applies the same history ids from the binary; CLI stays for ops.

Replace the filesystem loop in [`apply_pending_migrations`](src/db.rs) with:

```rust
static MIGRATIONS: toasty::migration::MigrationSet =
    toasty::embed_migrations!("toasty");

let report = MIGRATIONS.apply(&db).await?;
```

Keep `vcp migration` / `ToastyCli` in [`src/main.rs`](src/main.rs) and `+POST_INSTALL` (idempotent skip when embed already applied). Dev still `just db-migrate-generate` to disk; rebuild re-embeds. Same `__toasty_migrations` table.

Document the compile vs runtime gap: embed path is `CARGO_MANIFEST_DIR` at compile time; CLI still reads `Config::package_root()`.

**Pyramid (`toasty_migrations` — extend, do not fork):**

- Unit: `report.applied()` / `report.skipped()` on a second `apply` is empty.
- Invariants: lint must pin `embed_migrations!` **and** `apply_pending_migrations` (wrapper stays). Still pin `run_migration` + no `vcp-cli`.
- Proptest: keep synthetic `History` uniqueness; add pins on the **real** `toasty/history.toml` (unique ids/names, each name has a `migrations/*.sql` file). Second `MigrationSet::apply` skips all known ids.
- Battle: existing [`toasty_migrations_battle_test.rs`](tests/integration_tests/toasty_migrations_battle_test.rs) parallel `connect` / apply stays idempotent (now via embed).
- E2E: existing CRUD after `db::connect`; add **parity**: `vcp migration apply` (CLI / `package_root`) then `db::connect` (embed) on the same DB — `__toasty_migrations` ids match, no double-apply, no SQL drift.
- Invariants (pkg): pin `migration apply` in [`pkg/+POST_INSTALL`](pkg/+POST_INSTALL) and `Toasty.toml` + `toasty/` staging in [`pkg/build-pkg.sh`](pkg/build-pkg.sh) via [`scripts/check_freebsd_pkg.sh`](scripts/check_freebsd_pkg.sh) (filesystem payload stays until embed is proven).
- Smoke: runbook section — hybrid (embed at boot, CLI in `+POST_INSTALL`). Confirm ids never diverge; pkg upgrade must not drop `vcp`.

Do **not** delete `toasty/migrations/*.sql` from the pkg payload until embed is proven on staging.

---

## Lot 3 — Cursor pagination on full scans

**Goal:** use 0.10 `.paginate()` + `Page` where VCP today loads an entire table. Shared helper (new small module, e.g. `src/toasty_page.rs`) so seed/bundle/resync cannot drift:

```rust
.order_by(Model::fields().id().asc())
.paginate(BATCH)
.exec(db)
// while let Some(next) = page.next(db).await?
```

End-of-list = `next()` is `None` / `!has_next()`, not `len < BATCH`. Never chain `.paginate()` with `.limit()` / `.offset()`.

**Convert (scans):**

- [`resync_release_sort_keys`](src/db.rs) — `Release::all().exec()`
- [`export_articles_to_dir`](src/docs_bundle.rs) — all articles + `.include(body)` (0.10 preserves cursors)
- [`refresh_thin_doc_bodies`](src/db.rs) — all articles + include body
- [`ensure_demo_issue_comments`](src/db.rs) — all issues
- [`delete_org_objects`](src/storage/objects.rs) if it still `exec()`s the full org set
- [`purge_expired_tokens`](src/magic_link.rs) — all expired tokens (table grows with logins)

**Do not convert:** SSR lists; [`drain_pending_rows`](src/issue_notify.rs) (already `.limit(DRAIN_BATCH)` + sweeper); [`load_releases_for_org`](src/app/org/builds.rs) (bounded catalog, not a pager); [`allocate_issue_key`](src/issue_key.rs); point lookups (Lot 4).

**Pyramid (new surface `toasty_paginate_*`, plus extend `docs_bundle` / `seed_data`):**

- Unit: helper visits all ids, no duplicates, empty table, `per_page` upper bound.
- Invariants: [`scripts/check_toasty_filters.sh`](scripts/check_toasty_filters.sh) / new `scripts/check_toasty_paginate.sh` — those functions contain `.paginate(`; forbid bare `Release::all().exec` / `DocArticle::all().exec` in them. Pin “no mix paginate+offset”.
- Proptest: random table sizes vs batch sizes — union of page ids equals full set, intersection empty.
- Battle: concurrent `resync` / export under a barrier (no lost updates / no panic).
- E2E: seed or bundle with **> batch** fixtures (e.g. 11+ articles) — export count matches; resync is idempotent. Keep existing `docs_bundle_e2e` / `seed_data_e2e`.
- Smoke: extend [`docs/runbooks/docs_bundle_smoke_test.md`](docs/runbooks/docs_bundle_smoke_test.md) and/or a short `toasty_paginate_smoke_test.md` — export/import + `just seed-data` after the bump.

---

## Lot 4 — Unique lookups (not cursors)

**Goal:** stop loading whole tables to find one row. This is 0.9 API, required so Lot 3 is not misused as a lookup.

| Caller | Today | Replace with |
|--------|--------|----------------|
| [`run_seed_data`](src/main.rs) `all().len()` | full scan | `.count()` |
| [`ensure_demo_tenants`](src/db.rs) / `seed_minimal_if_empty` | `User::all` / `Organization::all` | `User::get_by_email`, `Organization::get_by_slug`, `.count()` for empty-DB |
| [`upsert_ga_releases`](src/db.rs) | all releases, filter GA in Rust | `.filter(organization_id.eq(GA))` or per-version filter (Release has **no** unique on `version`) |
| [`upsert_acme_private_release`](src/db.rs) | all orgs + all releases | `get_by_slug(acme-infrastructure)` + filter `version.eq(...)` |
| [`ensure_demo_issues`](src/db.rs) | all issues | `.filter(organization_id.eq).filter(key.in_list(["VBN-214","VBN-208"]))` |
| [`seed_demo_catalog`](src/db.rs) docs | `DocArticle::all()` then slug set | `.filter(slug.in_list(catalog_slugs))` or `.select(slug)` |
| [`org_context`](src/auth.rs) | `Organization::all().filter(slug)` | `get_by_slug` / `.limit(1)` (same for membership) |
| [`load_eph_for`](src/app/org/builds/ephemeral.rs) / `delete_existing_for` | filter `user_id` then Rust org+version | SQL `.filter(user_id).filter(organization_id).filter(release_version).limit(1)` |

`DocArticle` has **no** unique `(slug, version)` — import stays filtered `.limit(1)`, not `upsert_by_*`. Companies search-with-`q` still pages matched ids in Rust — leave unless a cheap `.order_by(name).limit().offset()` on `id.in_list` is obvious; not a 0.10 API.

**Pyramid (extend `seed_data_*` + `toasty_filters`):**

- Unit: empty vs existing email/slug; GA filter never sees org-private rows.
- Invariants: shrink the `db.rs` allowlist in `check_toasty_filters.sh`; pin `get_by_email` / `get_by_slug` / `.count()` in seed/CLI.
- Proptest: catalog sizes; second `seed_demo_catalog` does not duplicate keys.
- Battle: existing [`seed_data_battle_test.rs`](tests/integration_tests/seed_data_battle_test.rs).
- E2E: existing [`seed_data_e2e_test.rs`](tests/integration_tests/seed_data_e2e_test.rs) counts; switch test assertions to `.count()` where they only need totals.
- Smoke: runbook B in `toasty_migrations_smoke_test.md` (`just seed-data` counts).

---

## Lot 5 — `upsert_by_*` on real unique keys

**Goal:** prove the 0.9 upsert API (playbook: adopt on the bump) on keys that already exist.

- [`upsert_release_object`](src/storage/objects.rs) / [`upsert_image_object`](src/storage/objects.rs): model is `#[unique(scope, object_key)]` — use generated `upsert_by_scope_and_object_key` (or the exact 0.10 helper name) with `on_update` for sha/size/`updated_at`. Keep digest validation in Rust.
- Second site (in this lot, not optional): [`enqueue_issue_notify`](src/issue_notify.rs) today is `create!` + `is_unique_violation`. Switch to `IssueMailOutbox::upsert_by_issue_id_and_event_and_source_id_and_recipient_user_id(..., or_ignore)` (exact generated name after bump). Respect `#[version]` OCC — do not invent a second outbox path.

Do **not** invent unique indexes just to call upsert (no `Release.version` unique, no `DocArticle` slug+version unique).

**Pyramid (extend `storage_*` / `issue_notify_*`):**

- Unit: insert then update same key; invalid sha still denied.
- Invariants: pin `upsert_by_` in `objects.rs`; `check_storage` / existing storage lint if present.
- Proptest: random sha/size pairs — last write wins, one row per key.
- Battle: existing [`storage_battle_test.rs`](tests/integration_tests/storage_battle_test.rs) concurrent mirror writes.
- E2E: existing [`storage_e2e_test.rs`](tests/integration_tests/storage_e2e_test.rs) + seed still mirrors release objects.
- Smoke: storage / issue-notify runbooks already in tree — add “upsert idempotent” Pass/Fail.

---

## Explicit non-goals (later, not this campaign)

- Filtered `.include(comments.order_by(...))` on issue detail (0.9; optional follow-up).
- Multi-page drain of the mail outbox (current batch + sweeper is enough).
- Dropping filesystem `toasty/` from the FreeBSD pkg until Lot 2 is proven on staging.
