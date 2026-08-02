---
name: Companies page size search
overview: Set admin companies page size to 3 via a named COMPANIES_PAGE_SIZE constant, and add Topcoat live search (shard + re-auth) on /admin/companies modeled on admin Issues, with a full admin_companies test pyramid update.
todos:
  - id: const-helpers
    content: Add COMPANIES_PAGE_SIZE=3 + src/companies_search.rs helpers (unit/proptest) + lib.rs export; document in web-stack / list-pagination.mdc
    status: completed
  - id: shard-page
    content: Implement companies/search_shard.rs; wire q signals + list_toolbar + COMPANIES_PAGE_SIZE in companies.rs; move card markup into shard
    status: completed
  - id: pyramid
    content: Update check scripts + admin_companies invariants/proptest/battle/e2e; add admin_companies_search_shard_* tests + common shard body helper
    status: completed
  - id: runbook
    content: "Update admin_companies_smoke_test.md: C=3 cards, D=live search; severity A–D"
    status: completed
  - id: validate
    content: fmt-check + clippy -D warnings + both check scripts + just test -- admin_companies
    status: completed
isProject: false
---

# Admin companies: page size 3 + live search shard

## Locked decisions

- **Page size:** `COMPANIES_PAGE_SIZE = 3` in [`src/list_page.rs`](src/list_page.rs) (next to `LIST_PAGE_SIZE = 10`). Tables keep 10; card list uses 3. Document the exception in [`web-stack` skill](.cursor/skills/web-stack/SKILL.md) § List pagination and [`list-pagination.mdc`](.cursor/rules/list-pagination.mdc).
- **Search UX:** one live `type="search"` field (`q`), same idiom as [`/admin/issues`](src/app/admin/issues.rs) — GET form progressive enhancement + `@input` signal + Topcoat `#[shard]`. No status chips / no second org box (companies *are* orgs).
- **Match fields** (case-insensitive substring after `normalize_query`): org `name`, `slug`, `technical_contact`, `vat`, `address`, and membership account emails.
- **Auth on every shard POST:** `require_staff` then `companies_manage` then load (layout does not run on `/_topcoat/shards/{id}`).
- **Pagination + search:** pager stays SSR `list_toolbar` (no chips); hrefs keep `q` + `page`, never sticky `delete` / `err`. `@input` resets page signal to `"1"`. Shard slices with `COMPANIES_PAGE_SIZE`.
- **Delete overlay:** stays on the page (`?delete=`); trash links in shard → `/admin/companies?delete={id}` (optionally preserve `q`). Resolve delete target against the full unfiltered card list.
- **Surface name:** extend `admin_companies` (filter matches `admin_companies_*` and `admin_companies_search_shard_*`).

```mermaid
flowchart LR
  page["GET /admin/companies"] --> signals["signals q page"]
  signals -->|POST shard| shard["admin_companies_search_results"]
  shard --> auth["require_staff + companies_manage"]
  auth --> filter["companies_search helpers"]
  filter --> slice["page_slice COMPANIES_PAGE_SIZE"]
  slice --> cards["Company cards HTML"]
```

## 1. Shared constant + helpers

[`src/list_page.rs`](src/list_page.rs):

```rust
pub const COMPANIES_PAGE_SIZE: usize = 3;
```

New [`src/companies_search.rs`](src/companies_search.rs) (mirror [`src/issues_search.rs`](src/issues_search.rs) / [`src/docs_search.rs`](src/docs_search.rs)):

- `normalize_query`
- `company_matches_query(q, name, slug, contact, vat, address, emails: &[String])`
- Unit + colocated proptest (`companies_search_*`)
- `pub mod companies_search` in [`src/lib.rs`](src/lib.rs)

## 2. Shard + page wiring

New [`src/app/admin/companies/search_shard.rs`](src/app/admin/companies/search_shard.rs):

- `#[shard] pub async fn admin_companies_search_results(cx, q: String, page: String)`
- Gate order: `require_staff` → `companies_manage` → load orgs/memberships/users
- Drop reserved `vauban`; filter via helpers; sort by name; `page_slice(..., COMPANIES_PAGE_SIZE)`
- Render current card markup (`vb-company-card`, pills, Edit, trash); mark root `data-admin-companies-search-shard="1"`
- Empty: `"No matching companies."` / `"No companies."` when `q` empty and none

Refactor [`src/app/admin/companies.rs`](src/app/admin/companies.rs):

- `mod search_shard;` + `pub(super) use …`
- Query: add `q: Option<String>`; keep `delete` / `err` / `page`
- Build cards → filter by `q` → `page_count` / pager with `COMPANIES_PAGE_SIZE` and `q` in hrefs
- Chrome: title/CTA; GET search form (`vb-search`, `@input` → `page.set("1"); query.set(...)`); `list_toolbar`; invoke shard with `q: $(query.get()), page: $(page.get())`
- Remove inline card loop from the page (shard owns the list); keep delete confirm overlay on the page

## 3. Conventions

- [`web-stack` skill](.cursor/skills/web-stack/SKILL.md): default `LIST_PAGE_SIZE=10`; **exception** `COMPANIES_PAGE_SIZE=3` for admin company cards.
- [`list-pagination.mdc`](.cursor/rules/list-pagination.mdc): point at both constants.

## 4. Pyramid (`admin_companies`)

| Layer | Deliverable |
|-------|-------------|
| **Unit** | `companies_search` normalize/match; existing `list_page` helpers |
| **Invariants** | Extend [`scripts/check_admin_companies.sh`](scripts/check_admin_companies.sh): `COMPANIES_PAGE_SIZE`, shard file `#[shard]` + `require_staff` + `companies_manage` before load, no `path_param`, page wires signals + GET form + shard call. New thin [`scripts/check_admin_companies_search_shard.sh`](scripts/check_admin_companies_search_shard.sh) (gate order) invoked from invariants (same pattern as issues). Update [`admin_companies_invariants_test.rs`](tests/integration_tests/admin_companies_invariants_test.rs). |
| **Proptest** | Pin `COMPANIES_PAGE_SIZE == 3`; match case-insensitivity / normalize idempotence in `companies_search` + [`admin_companies_proptest.rs`](tests/integration_tests/admin_companies_proptest.rs) / new `admin_companies_search_shard_proptest.rs` |
| **Battle** | Retarget pagination battle to size 3 (seed ≥4 listable orgs); add parallel shard POSTs under contention → 200 (pattern [`admin_issues_search_shard_battle_test.rs`](tests/integration_tests/admin_issues_search_shard_battle_test.rs)) |
| **E2E** | Pagination: seed **4** fixtures → page 1 = **3** `class="vb-company-card"`, page 2 remainder. Search: staff cookie → capture shard path from HTML → POST `q` matches name/email; empty `q` returns broader set; anon / member → **404**, no foreign org names. Helper `admin_companies_search_shard_body` in [`tests/integration_tests/common/`](tests/integration_tests/common/) |
| **Smoke** | Update [`docs/runbooks/admin_companies_smoke_test.md`](docs/runbooks/admin_companies_smoke_test.md): **C** = 3 cards + toolbar; **D** = live search shard (Network `/_topcoat/shards`, denial paths). Severity A–D. |

## 5. Validation

```bash
just fmt
rtk cargo fmt --all -- --check
rtk cargo clippy --all-targets -- -D warnings
bash scripts/check_admin_companies.sh
bash scripts/check_admin_companies_search_shard.sh
just test --test integration_tests -- admin_companies -- --test-threads=1
```

## Out of scope

- DB `LIMIT/OFFSET`
- Search on admin docs/releases
- Changing global `LIST_PAGE_SIZE`
- Magic-link / SMTP
