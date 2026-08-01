---
name: Builds list pagination
overview: Add SSR builds pagination (10 per page) via Topcoat `#[query_params]` + shareable GET links, reset page on channel change, and extend the builds_entitlement pyramid end-to-end.
todos:
  - id: page-helpers
    content: BuildsQuery.page + PAGE_SIZE=10 + parse/slice helpers + wire list/detail
    status: completed
  - id: page-ui
    content: SSR pager links + CSS; channel chips reset page; preserve page on collapse
    status: completed
  - id: page-pyramid
    content: Extend builds_entitlement unit/invariants/proptest/battle/e2e + runbook F
    status: completed
  - id: page-validate
    content: fmt, clippy, check_builds_entitlement, just test builds_entitlement_
    status: completed
isProject: false
---

# Builds list pagination (10 per page)

## Decisions (locked)

- **Surface:** extend **builds_entitlement** (no new surface name).
- **Page size:** `const BUILDS_PAGE_SIZE: usize = 10` in [`src/app/org/builds.rs`](src/app/org/builds.rs).
- **Topcoat idiom:** SSR only — extend `BuildsQuery` with `page: Option<u32>` (1-based). Navigation via `<a href>` (reuse `vb-chip` / small `vb-pager` styles). No shards, signals, or first-party JS for paging.
- **Channel × page:** channel chips link **without** `page` (implicit reset to page 1). Pager links keep `channel` when set; omit `page=1` from URLs.
- **Default-open:** only when `page == 1` (or omitted) and not `open=none` — open the first row of the current page slice (still highest version overall, since page 1 is the top of the sorted list).
- **Deep-link** `/{org}/builds/{ver}`: load full sorted visible list, find index of `ver`, derive `page = index / 10 + 1`, render that page’s slice with `ver` open (preserve `channel` filter). Do not leave the open build off-page.

## Implementation

### Query + slice helpers ([`builds.rs`](src/app/org/builds.rs))

```rust
#[query_params]
pub(super) struct BuildsQuery {
    pub channel: Option<String>,
    pub open: Option<String>,
    pub page: Option<u32>,
}
```

- `fn parse_page(raw: Option<u32>) -> usize` — default `1`, clamp `max(1, raw)`.
- `fn page_count(total: usize, page_size: usize) -> usize`.
- `fn page_slice<T>(items: &[T], page: usize, page_size: usize) -> &[T]` (or owned indices).
- After existing `load_releases_for_org` + `sort_releases`: compute `total`, clamp page to `page_count`, slice, pass `page` / `page_count` / `total` into `render_builds`.

### UI

- Below the builds table: pager only when `page_count > 1`.
  - Prev / Next links (disabled as non-link `span` when at ends).
  - Compact page number links (same chip language as filters).
  - URL builder: `/{org}/builds?channel=LTS&page=2` (skip empty channel; skip `page=1`).
- Channel chips: keep current hrefs **without** `page`.
- Collapse / expand row hrefs: preserve `page` + `channel` when present so paging state survives collapse.
- Ephemeral PRG redirect ([`ephemeral.rs`](src/app/org/builds/ephemeral.rs)): keep `channel` only (detail path re-derives page from version) — no `page` required on POST redirects.

### Detail route ([`release_ver.rs`](src/app/org/builds/release_ver.rs))

- After visibility check, sort full list, locate `ver`, set `page` from index, slice, open that version.
- Accept optional `page` in query but **prefer computed page** from version so deep-links stay consistent.

### CSS ([`styles.css`](styles.css))

- Minimal `.vb-pager` / `.vb-pager-link` (flex row, gap, muted disabled state) — no new design system; align with Concept chips/buttons already used on Builds.

## Pyramid (builds_entitlement)

| Layer | Deliverable |
|-------|-------------|
| **Unit** | `page_slice` / `parse_page` / `page_count` tests (empty, exact 10, 11→2 pages, page clamp past end). |
| **Invariants** | [`scripts/check_builds_entitlement.sh`](scripts/check_builds_entitlement.sh) + [`builds_entitlement_invariants_test.rs`](tests/integration_tests/builds_entitlement_invariants_test.rs): `BUILDS_PAGE_SIZE` / `page_size` = 10; `BuildsQuery` has `page`; pager markup (`vb-pager`); channel chip hrefs must not hardcode sticky `page=`; no client JS pager. |
| **Proptest** | [`builds_entitlement_proptest.rs`](tests/integration_tests/builds_entitlement_proptest.rs): for totals `0..=40`, `page_count` and slice lengths are correct; out-of-range page clamps. |
| **Battle** | [`builds_entitlement_battle_test.rs`](tests/integration_tests/builds_entitlement_battle_test.rs): parallel GETs `?page=1` and `?page=2` (with ≥11 fixture releases) return OK and distinct version markers. |
| **E2E** | [`builds_entitlement_e2e_test.rs`](tests/integration_tests/builds_entitlement_e2e_test.rs): seed 11+ GA releases; page 1 has 10 rows + default-open highest; page 2 has remainder; channel chip URL drops `page`; deep-link to a page-2 version opens on the correct page. |
| **Smoke** | [`docs/runbooks/builds_entitlement_smoke_test.md`](docs/runbooks/builds_entitlement_smoke_test.md) section **F -- Pagination**: 10 max, next/prev, channel resets page, deep-link preserves open build. |

## Validation

```bash
just fmt
just clippy
bash scripts/check_builds_entitlement.sh
just test builds_entitlement_
```

## Out of scope

- DB-level `LIMIT/OFFSET` (in-memory slice after current sort/filter is enough at catalog size).
- Paginating admin `/admin/releases`.
- Changing verify / ephemeral panel behavior beyond URL preservation rules above.
