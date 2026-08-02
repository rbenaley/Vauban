# VCP architecture audit — Toasty query debt

**Date:** 2026-08-02  
**Source:** External static review of the VCP archive (Topcoat 0.5 SSR,
Toasty 0.9 / PostgreSQL), cross-checked against the Toasty 0.9.0 crate
sources. Original French write-up was provided as
`audit-architecture-vcp.md` (local Downloads); this file is the
repo-tracked English summary focused on ORM findings.  
**Audience:** agents and engineers changing list / search / entitlement
loaders.  
**Normative follow-up:** `.cursor/skills/toasty/SKILL.md`.

---

## Status (2026-08-02 remediation)

**Findings 3.1–3.5 are remediated** in-tree (shared helpers + waves A–E).
Enforcement: `scripts/check_toasty_filters.sh`, `toasty` skill, list-
pagination / web-stack notes. Intentional leftovers:

- Release **semver** order stays Rust `cmp_version_desc` after a
  SQL-bounded set (no `sort_key` column yet).
- Admin releases staff catalogue may still load the global release set
  then sort/page in Rust (same semver exception).
- Seed / `db.rs` may use unfiltered `::all()` for bootstrap only.

---

## Executive takeaway (original)

VCP is strong on portal security (anti-enumeration, TLS 1.3, CSRF,
Casbin + tenancy). The main architectural debt was systematic
**full-table load then filter/sort/page in Rust**
(`Model::all().exec()` + `page_slice` / Rust predicates). That is
**not** a Toasty limitation: 0.9 already exposes `limit` / `offset` /
`count` / `order_by` / `ilike` / `in_list` / `.or`.

Highest-severity instance (fixed): org builds previously loaded **all**
releases then applied `release_visible_to_org` in process — now SQL
`status` + `organization_id.in_list` (GA + org) with Rust as
defense-in-depth.

---

## Findings (Toasty-related)

| ID | Severity | Issue | Fix direction | Status |
|----|----------|-------|---------------|--------|
| 3.1 | High | `load_releases_for_org` uses `Release::all()` + Rust entitlement | SQL `in_list` / `.or` on `organization_id` (GA + org) | Remediated |
| 3.2 | Medium | `User::all()` / `Organization::all()` for display lookups | `.filter(id.in_list(page_ids))` | Remediated |
| 3.3 | Medium-High | Search shards full-scan then Rust match | `.ilike` + `order_by` + `limit`/`offset` | Remediated |
| 3.4 | Medium | `page_slice` after full load | SQL `limit`/`offset` (note: `offset` requires prior `limit`) | Remediated (releases semver exception) |
| 3.5 | Low | `membership_count` via `rows.len()` | `.count()` | Remediated |

Other audit items (in-memory login rate limit, young 0.x deps, onboarding
mail, `unwrap` triage) are out of scope for the Toasty skill but remain
product/ops follow-ups.

---

## API confirmation (Toasty 0.9.0)

Verified in upstream `stmt/query.rs` / `stmt/path.rs` / guide:

- `.limit(n)` — upper bound; post-DB filtering may shorten results
- `.offset(n)` — panics without a prior `.limit`
- `.count()` — `COUNT(*)`
- `.order_by(field.asc()|.desc())` — tuples for tie-breakers
- String search: `.like` / `.ilike` (Postgres) / `.starts_with`
- Multi-value: `.in_list([...])`, combine with `.or` / `.and`
- `.contains` on paths targets **array** (`Vec` scalar) fields, not
  substring on `String` — use `.ilike("%…%")` for text contains

---

## Suggested order of work

1. Release entitlement SQL (3.1) — security net  
2. Search shards + SQL pagination (3.3 + 3.4)  
3. Targeted id lookups (3.2) and `.count()` seats (3.5)  
4. Optional shard debounce / rate limit as traffic grows  

When implementing, follow the full `vcp-test-pyramid.mdc` on auth /
tenant / entitlement surfaces.
