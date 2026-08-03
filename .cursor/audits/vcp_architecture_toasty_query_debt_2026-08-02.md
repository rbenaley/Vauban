# VCP architecture audit — Toasty query debt

**Version:** 2 — reassessment after remediation  
**Dates:** 2026-08-02 (v1 summary) · 2026-08-03 (v2 update)  
**Scope:** Toasty / PostgreSQL query patterns only (list, search, entitlement,
lookups, counts). Non-ORM items from the external review are noted only as
out-of-scope pointers.  
**Source:** External static review (`audit-architecture-vcp.md` v2),
cross-checked against Toasty 0.9.0 crate sources and in-tree commits
`8951226` (*fix(toasty): push hot-path filters into SQL (audit 3.1-3.5)*)
and `ddd784b` (*perf(db): cut duplicate list SQL and dashboard issue COUNT
fan-out*).  
**Audience:** agents and engineers changing list / search / entitlement
loaders.  
**Normative follow-up:** `.cursor/skills/toasty/SKILL.md`.

---

## Status (v2)

| ID | Severity | Status |
|----|----------|--------|
| 3.1 | High | **Remediated** — SQL entitlement + Rust defense-in-depth |
| 3.2 | Medium | **Remediated** — `id_lookups` + page-scoped ids |
| 3.3 | Medium-High | **Remediated** — SQL `ILIKE` (escaped) + bounded pages; shard debounce still open (no first-party JS) |
| 3.4 | Medium | **Remediated** — SQL `limit`/`offset` including builds / admin releases via sort columns |
| 3.5 | Low | **Remediated** — `membership_count` via `.count()` |
| 3.10 | Medium | **Remediated** — unique `(organization_id, key)`, `allocate_issue_key` + retry, honor `create!` |

Intentional leftovers (documented, not regressions):

- Seed / `db.rs` may use unfiltered `::all()` for bootstrap / resync only.
- Release list detail deep-links may scan the org-visible ordered set to
  compute page index (still SQL-ordered; list pages use `limit`/`offset`).

Enforcement: `scripts/check_toasty_filters.sh`, `toasty` skill, list-
pagination / web-stack notes, surface smoke runbooks.

---

## Executive takeaway

VCP is strong on portal security (anti-enumeration, TLS 1.3, CSRF,
Casbin + tenancy). The main Toasty debt from v1 — systematic **full-table
load then filter/sort/page in Rust** — is **not** a Toasty limitation:
0.9 already exposes `limit` / `offset` / `count` / `order_by` / `ilike` /
`in_list` / `.or`.

Commits `8951226` and `ddd784b` pushed entitlement, search, pagination,
counts, and id lookups into SQL, with request-scoped `#[memoize]` for
shared `COUNT` / list work, and structural lint + runbook locks against
regression.

Cross-tenant release leak risk from v1 (§3.1) is closed. §3.10 (issue key
allocation) is remediated: unique `(organization_id, key)`, org-scoped
allocator with retry on unique conflict, and failed creates redirect to
`?err=create` instead of a ghost detail URL. Shard debounce (#6) stays
open: no first-party JS / no Topcoat-native debounce yet.

---

## Findings (Toasty-related)

### 3.1 — Remediated — [High] Release entitlement only in Rust

**Where:** `src/app/org/builds.rs` — `load_releases_for_org`,
`find_visible_release_by_version`

**v1:** `Release::all()` then `release_visible_to_org` in process — private
releases of other tenants entered memory.

**v2:** SQL net is primary — `status = PUBLISHED`, then
`organization_id.in_list([RELEASE_GA_ORG_ID, org_id])` except reserved
staff tenant; channel `eq` when set. Rust predicate kept as
defense-in-depth. Version lookup got the same SQL lock. Semver sort remains
Rust on the bounded set.

**Follow-up:** none for this finding.

### 3.2 — Remediated — [Medium] Full-table loads for display lookups

**v1:** `User::all()` / `Organization::all()` to resolve a few display
names.

**v2:** `src/id_lookups.rs` — `users_by_ids` / `orgs_by_ids` with
`.filter(id().in_list(unique))`, empty short-circuit, unit tests. Search
shards collect page `opened_by_user_id` values only. Org dashboard
(`ddd784b`): one org-scoped capped issue query
(`limit(DASHBOARD_ISSUES_CAP)` = 500) instead of per-tile `COUNT` fan-out.

**Follow-up:** none for this finding.

### 3.3 — Remediated — [Medium-High] Search shards full-table scan

**Where:** admin/org issue and docs search shards; companies load/search.

**v1:** full table load then Rust filter/sort/page, no `LIMIT`.

**v2:** shared query macros (`org_issues_filtered_query!`,
`admin_issues_filtered_query!`, docs equivalent) — tenant `eq`, status
`eq`, text `ilike_with_escape` on key + title. Companies search covers org
fields in SQL and orgs via account email (`User.email ILIKE` → memberships
→ org ids). Escape helpers in `src/sql_search.rs` (`ilike_contains` /
`escape_ilike_literal`) with unit + proptest coverage. Result counts
request-memoized (`#[memoize]`) so HTML page + embedded shard share one
SQL `COUNT` (`ddd784b`).

**Follow-up (non-SQL):** client debounce / shard rate limit still open
(no hand-written `setTimeout` / `raw!` JS; wait for Topcoat-native debounce
or a separate server design).

### 3.4 — Remediated — [Medium] In-memory pagination

**v1:** `page_slice()` on fully loaded `Vec`s.

**v2:** issues, docs, companies — SQL `count()` → clamp page →
`.order_by(updated_at.desc()).limit(LIST_PAGE_SIZE).offset(...)`.
Toasty rule respected: `offset` requires prior `limit`.

**v2.1 (semver closed):** `Release` materializes `v_major` / `v_minor` /
`v_patch` / `has_client_suffix` / `client_suffix` (migration `0008`).
Org Builds and `/admin/releases` use tuple `order_by` + `limit`/`offset`.
Pure `cmp_version_desc` remains for unit/proptest only.

**Follow-up:** none for this finding.

### 3.5 — Remediated — [Low] Seat count without SQL `COUNT`

**Where:** `src/seats.rs::membership_count`

**v2:** `.filter(organization_id.eq(...)).count().exec(db)` — true
`COUNT(*)`.

**Follow-up:** none.

### 3.10 — Remediated — [Medium] Issue key generation + swallowed insert

**Where:** `src/app/org/issues.rs` — `report_issue`
(`POST /{org}/issues`); helper `src/issue_key.rs`; migration
`0009_issue_org_key_unique.sql`

**v2 fix:**

1. **Unique constraint** `UNIQUE (organization_id, key)`.
2. **Allocator** `allocate_issue_key` — org-scoped keys, parse `VBN-{n}`,
   `next = max(199, max_seen) + 1` (empty org → `VBN-200`).
3. **Create with retry** (up to `ISSUE_KEY_CREATE_ATTEMPTS`) on unique
   violation; other errors fail closed.
4. **Honor `create!`** — success → detail; exhausted / other failure →
   `see_other("/{org}/issues?err=create")` + `tracing::warn!` (never a
   ghost detail URL).

**Follow-up:** optional list flash for `?err=create`; sequence/`MAX` if
org issue volume makes full key-list allocation hot (not required now).

---

## Out of Toasty scope (from external v2 review)

Not tracked as ORM debt here; product / ops follow-ups only:

- In-process login rate limiter (multi-instance)
- ~~Real mail + magic links (onboarding)~~ — **Done** (passwordless SMTP magic links, soft-delete accounts, invite/revoke mails)
- `unwrap()` triage outside tests
- Young 0.x Topcoat / Toasty churn risk (API capability confirmed below)

---

## API confirmation (Toasty 0.9.0)

Verified upstream and exercised in-tree after v2 remediation:

| Need | v1 code | Toasty 0.9 API | v2 status |
|------|---------|----------------|-----------|
| Pagination | `page_slice` after `all()` | `.limit(n)` / `.offset(n)` | Used (issues, docs, companies) |
| Count | `rows.len()` after `all()` | `.count()` → `COUNT(*)` | Used (lists, seats); request-memoized |
| Sort | Rust `sort_by_key` | `.order_by(field.asc()/.desc())` | Used (`updated_at desc` + release semver columns) |
| Text search | Rust `.contains()` | `.like` / `.ilike` / `_with_escape` | Used; centralized escape + proptest |
| Multi-value | Rust post-filter | `.in_list([...])` / `.or(...)` | Used (builds entitlement, id lookups) |

Notes: `.offset()` panics without a prior `.limit`; `.limit()` is an upper
bound if further filtering happens after the DB round-trip (N/A when all
filters are SQL). Path `.contains` targets **array** fields, not substring
on `String` — use escaped `ILIKE` for text contains.

---

## Suggested order of work (Toasty)

| # | Action | Severity | Status |
|---|--------|----------|--------|
| 1 | Release entitlement in SQL | High | Remediated (`8951226`) |
| 2 | Search shard filters in SQL | Medium-High | Remediated (`8951226`) |
| 3 | SQL `limit`/`offset` on paginated lists | Medium | Remediated (`8951226`; semver columns `0008`) |
| 4 | Targeted id lookups | Medium | Remediated (`8951226`, `ddd784b`) |
| 5 | `membership_count` via `.count()` | Low | Remediated (`8951226`) |
| 6 | Shard debounce / rate limit | Low (was Medium) | Open — deferred (no first-party JS debounce) |
| 10 | Safe issue key allocation + honor `create!` | Medium | **Remediated** |

When touching auth / tenant / entitlement / issue create, deliver the full
`vcp-test-pyramid.mdc`.

---

## Synthesis

v2 confirms the v1 root cause — systematic full-table loads — was fixed in
depth: tenant and entitlement filters in SQL with Rust defense-in-depth,
escaped `ILIKE` with property tests, native pagination and counts, targeted
lookups, request memoization, and structural lint / runbook locks.

Cross-tenant release risk (§3.1) is closed; the semver list exception (§3.4)
and issue-key races (§3.10) are closed. Shard search debounce (#6) remains
open without first-party JS. Product/ops items (shared login store, magic
links, unwrap triage) stay out of Toasty scope.
