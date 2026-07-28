---
name: Issues live search shards
overview: Appliquer le même pattern que docs (Topcoat shard + ré-auth + helpers purs) aux deux seules autres zones de recherche existantes — `/{org}/issues` et `/admin/issues` — chacune avec une pyramide de tests complète.
todos:
  - id: helpers
    content: Add src/issues_search.rs pure helpers + unit/proptest; export from lib.rs
    status: completed
  - id: org-shard
    content: Org issues search_shard + wire signals in org/issues.rs
    status: completed
  - id: admin-shard
    content: Admin issues search_shard + wire q/org signals in admin/issues.rs
    status: completed
  - id: check-scripts
    content: scripts/check_{org,admin}_issues_search_shard.sh
    status: completed
  - id: pyramid-org
    content: Full pyramid org_issues_search_shard + smoke runbook
    status: completed
  - id: pyramid-admin
    content: Full pyramid admin_issues_search_shard + smoke runbook
    status: completed
  - id: validate
    content: fmt, clippy, check scripts, just test -- issues_search_shard
    status: completed
isProject: false
---

# Issues live search shards

## Scope

Exactly **two** remaining `type="search"` surfaces (no search UI today on admin docs/companies/releases or builds):

| Surface | Page | Shard args | Re-auth |
|---------|------|------------|---------|
| Org issues | [`src/app/org/issues.rs`](src/app/org/issues.rs) | `org_slug`, `q`, `status` | `normalize_org_slug` → `require_org` → `issues_read` |
| Admin issues | [`src/app/admin/issues.rs`](src/app/admin/issues.rs) | `q`, `org`, `status` | `require_staff` → `issues_read` |

Status chips stay **GET navigation** (same as docs category chips). Live typing updates list via shard; chip clicks still reload with query params.

```mermaid
flowchart LR
  page["Page SSR GET"] --> signals["signals q / org"]
  signals -->|POST /_topcoat/shards/id| shard["#[shard]"]
  shard --> auth["Re-auth gates"]
  auth --> filter["Pure filter helpers"]
  filter --> html["Result rows HTML"]
```

## Implementation

### 1. Pure helpers — [`src/issues_search.rs`](src/issues_search.rs)

Mirror [`src/docs_search.rs`](src/docs_search.rs):

- `normalize_query`, `normalize_status`, `normalize_org_filter` (trim)
- `issue_matches_query(q, key, title)` (case-insensitive contains)
- `issue_matches_status(status, issue_status)`
- Reuse / move `resolve_org_filter(orgs, raw) -> Option<u64>` from admin issues here
- Re-export `normalize_org_slug` usage from `docs_search` for the org shard (no duplicate)
- Unit + colocated proptest named `issues_search_*` / `issues_search_prop_*`
- `pub mod issues_search` in [`src/lib.rs`](src/lib.rs)

### 2. Org issues shard

New [`src/app/org/issues/search_shard.rs`](src/app/org/issues/search_shard.rs):

- `#[shard] issues_search_results(cx, org_slug, q, status)`
- **Never** `path_param::<Org>` (same panic class as docs)
- Gate order: blank slug → `require_org` → `issues_read` → load + filter
- Links / tenant from `ctx.org` only
- Extract list-row markup into the shard; page keeps chrome (title, New, chips, form)

Wire in [`src/app/org/issues.rs`](src/app/org/issues.rs):

- `signal query = q_value`
- `@input` on search field
- Call shard with `org_slug: $(slug.clone())`, `q: $(query.get())`, `status: $(status.clone())`
- Keep GET form as progressive-enhancement fallback

### 3. Admin issues shard

New [`src/app/admin/issues/search_shard.rs`](src/app/admin/issues/search_shard.rs):

- `#[shard] admin_issues_search_results(cx, q, org, status)`
- Re-check `require_staff` + `issues_read` inside shard (layout does not run on shard POST)
- Two signals: `query` + `org_query` with `@input` on both search boxes
- Marker `data-admin-issues-search-shard="1"` (org shard: `data-issues-search-shard`)

### 4. Structural lints

- [`scripts/check_org_issues_search_shard.sh`](scripts/check_org_issues_search_shard.sh)
- [`scripts/check_admin_issues_search_shard.sh`](scripts/check_admin_issues_search_shard.sh)

Pins: `#[shard]`, no `path_param` on org shard, gate order, `ctx.org.slug` / no trusting raw args for links, page passes shard args, shared `issues_search` helpers.

### 5. Test pyramids (same depth as docs)

Two filters, parallel to `docs_search_shard`:

**`org_issues_search_shard`**

| Layer | Artifact |
|-------|----------|
| Unit | `src/issues_search.rs` + org-slug reuse |
| Invariants | `tests/.../org_issues_search_shard_invariants_test.rs` + check script |
| Proptest | production helpers + JSON body shape |
| Battle | parallel shard POSTs |
| E2E | match key/title; empty/forged/wrong-tenant/anon → 404; missing `issues_read` → 403 |
| Smoke | [`docs/runbooks/org_issues_search_shard_smoke_test.md`](docs/runbooks/org_issues_search_shard_smoke_test.md) |

**`admin_issues_search_shard`**

| Layer | Artifact |
|-------|----------|
| Unit | shared helpers (org filter resolve) |
| Invariants | `tests/.../admin_issues_search_shard_invariants_test.rs` + check script |
| Proptest | org filter resolve + query match |
| Battle | parallel admin shard POSTs |
| E2E | match + org filter; anon/member → 404/403; staff happy path 200 |
| Smoke | [`docs/runbooks/admin_issues_search_shard_smoke_test.md`](docs/runbooks/admin_issues_search_shard_smoke_test.md) — Network filter `/_topcoat/shards` on `/admin/issues` |

Reuse helpers from [`tests/integration_tests/common/mod.rs`](tests/integration_tests/common/mod.rs): `post_json`, `shard_path_from_html`, `login_cookie`; add `issues_search_shard_body` / `admin_issues_search_shard_body` and a small issue fixture creator if missing.

Register modules in [`tests/integration_tests/main.rs`](tests/integration_tests/main.rs).

### 6. Docs / skill note

Extend the existing shard warning in [`.cursor/skills/topcoat/references/RUNTIME.md`](.cursor/skills/topcoat/references/RUNTIME.md) with a one-liner that admin shards must re-run `require_staff` (no layout).

## Validation

```bash
just fmt
just clippy
bash scripts/check_org_issues_search_shard.sh
bash scripts/check_admin_issues_search_shard.sh
just test -- issues_search_shard
```

(Filter matches both `org_issues_search_shard_*` and `admin_issues_search_shard_*` plus unit `issues_search_*`.)

## Out of scope

- Adding brand-new search boxes to admin docs / companies / releases / builds channel chips
- Changing status chips to client-side signals (GET chips stay)