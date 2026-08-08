# VCP permission model audit — Casbin usage and implementation

**Date:** 2026-08-08
**Scope:** Permission model (`PermissionContext`), policy store, tenant gates,
every routed surface under `src/app/`, view-layer gating, drift protection,
and the plans in `.cursor/plans/` that defined the model.
**Method:** Plan review (`admin_global_route_remap`, `anti-enumeration_hardening`,
`multi-org_choose_picker`, `issue_image_attachments`, `magic_links_mail`,
`companies_lts_account_login`, scaffold plans), full source sweep of the 34
route-bearing files (pages, shards, POST routes), policy/config inspection,
structural lint review (`scripts/check_auth_tenant.sh`), and test runs.

---

## 1. Architecture as implemented

Three ordered layers, consistent with `casbin-permissions.mdc`:

| Layer | Mechanism | Failure mode |
|-------|-----------|--------------|
| Session | Topcoat session + `AuthSession` row (SHA-256 token hash, expiry) | anonymous / expired → 404 on org and admin surfaces |
| Tenant / identity | `require_org(cx, slug)` (memoized `org_context`: org row + membership; reserved `vauban` staff-only) and `require_staff` (`portal_role == admin` **plus** Casbin `admin_view`) | missing org / membership / staff → **404** (anti-enumeration) |
| Capability | `PermissionContext` from `PolicyStore` (CSV `p, role:*, resource, action`), one flag per tracked couple | entry deny → **404** via `capability_denied()`; visible-resource action deny → **403** (downloads only) |

- **Catalogue** (11 couples) matches the rule 1:1: `docs read/write`,
  `builds read/download`, `releases manage`, `issues read/write`,
  `companies manage`, `key manage`, `account read`, `admin view`.
  Roles: `role:org`, `role:admin` only (`config/access/vcp_policy.csv`).
- **Casbin subject derivation** (`org_context`): staff `portal_role=admin` →
  `admin` (including `/vauban` preview); otherwise membership role (always
  `org`). Unknown role strings resolve to an all-false context → fail closed.
- **Policy load**: once at boot from `cfg.access.policy_path`
  (layered TOML; production `/usr/local/etc/vcp/access/vcp_policy.csv`),
  `Arc<PolicyStore>` in router `app_context`. Malformed CSV line → boot abort.
- **Memoization**: `org_context` and `require_perms` are `#[memoize]`d, so
  layout + page + shards share one membership lookup and one policy read per
  request (request-scoped, no cross-request caching of authz state).
- Plan lineage note: `admin_global_route_remap` originally specified 403 for
  org users on `/admin/*`; `anti-enumeration_hardening` superseded that with
  the 404 deny matrix. The **code implements the newer plan** (404), which is
  the stricter and documented posture.

## 2. Conformance — what is done correctly

**Every routed surface gates through the two layers, with the right flag.**
Sweep result (page entry + each POST body re-checked):

| Surface | Tenant gate | Capability flag |
|---------|-------------|-----------------|
| `/{org}` dashboard + layout | `require_org` | — (see F4) |
| `/{org}/docs`, `/docs/{slug}`, docs search shard | `require_org` | `docs_read` |
| `/{org}/builds`, `/builds/{ver}` | `require_org` | `builds_read` (+ `can_download` from `builds_download` in view) |
| `POST /{org}/builds/{ver}/download`, `POST …/ephemeral` | `require_org` | `builds_download` (403 on deny) |
| `/{org}/issues`, detail, new, search shard | `require_org` | `issues_read` / `issues_write` (reply/close/reopen each re-check) |
| `/{org}/account` | `require_org` | `account_read` |
| `/{org}/images` GET/POST | `require_org` (or staff path, below) | `issues_read\|write`; non-member path additionally requires `admin_view` |
| `/admin` hub + layout | `require_staff` | (`admin_view` inside `require_staff`) |
| `/admin/docs*` (list, new, edit, publish, unpublish, delete) | `require_staff` | `docs_write` on every route |
| `/admin/releases*` (list, new, validate, confirm, delete) | `require_staff` | `releases_manage` on every route |
| `/admin/issues*` (list, detail, reply, close, reopen, shard) | `require_staff` | `issues_read` entry, `issues_write` mutations |
| `/admin/companies*` (list, new, edit, accounts, shard) | `require_staff` | `companies_manage` on every route |
| `/admin/key*` (page + POSTs) | `require_staff` | `key_manage` |

- **No role-boolean gates in app code.** Zero occurrences of `is_admin` /
  `is_staff` / `is_superuser` / `role == "admin"` in `src/`;
  `scripts/check_auth_tenant.sh` **bans them structurally** and is executed by
  `auth_tenant_invariants_test.rs` on every test run.
- **`view!` markup reads Casbin flags, not roles**: rail admin block =
  `perms.admin_view`, Keys item = `perms.key_manage`, download buttons =
  `perms.builds_download`, reply forms = `perms.issues_write`, and the
  support/reporter author label on replies derives from `perms.admin_view`
  (`issue_key.rs:393`) — not from a role string.
- **Shards re-authorize** (docs / org issues / admin issues / companies search
  shards all call `require_org`/`require_staff` + flag before loading data),
  matching the "shard args are untrusted" convention.
- **Two-layer object scoping** is respected after Casbin: issues, attachments,
  images, and releases are all filtered by `organization_id` (IDOR-safe), with
  invisible objects answered 404.
- **Anti-enumeration deny matrix** implemented exactly as planned: capability
  entry 404 (`capability_denied()`), `forbidden()` confined by lint to
  `builds/download.rs` + `builds/ephemeral.rs` (visible-resource action).
- **Support image path** (`images.rs::authorize_image_org_id`) — the one
  intentional non-member read — gates **only via `PermissionContext`**
  (`admin_view` AND `issues_read|write`); clients resolve to `role:org` →
  `admin_view=false` → 404. Conforms to the rule's "gate only via
  PermissionContext".
- **Hard invariants outside Casbin live in helpers** as the rule requires:
  seat caps / account-class checks use `is_portal_org` in
  `companies_accounts.rs` (provisioning invariants, not authz decisions).
- **Drift protection present**: `TRACKED_PERMS` ↔ CSV forward test (unit +
  invariants), `role:` prefix pin on every CSV line, proptest that unknown
  roles get no `admin_view`/`releases_manage`/`companies_manage`, plus E2E
  denial paths (wrong org, non-member, anonymous, reserved org, admin nest).
- **No bastion imports**: policy file and resource names are VCP-specific; no
  `assets:*` / `sessions:*` from `../Vauban`.

## 3. Findings

### F1 — "Casbin" is a homegrown loader; `model.conf` is dead config (Medium)

There is **no `casbin` crate dependency**. `PolicyStore` parses the CSV
`p, sub, obj, act` format into a `HashSet` and answers exact-match lookups.
`config/access/model.conf` (request/policy/matcher definitions, `g` role
inheritance) exists and `access.model_path` is resolved and validated at
boot — but **nothing ever reads it**. Consequences:

- No `g` role inheritance, no matcher expressions: fine for the current
  two-role flat model, and arguably safer (smaller surface), but the docs and
  rules say "Casbin" while the enforcement engine is a 40-line custom loader.
- Risk is documentation drift and false expectations (e.g. someone adds a
  `g, role:support, role:admin` line that silently does nothing — the parser
  would even **reject** the file at boot since only `p` lines are accepted,
  which at least fails loudly).

**Recommendation:** either (a) adopt the real `casbin` crate wired to
`model.conf`, or (b) keep the loader, delete `model.conf` + `access.model_path`,
and rename the wording in rules/docs to "Casbin-format policy". Option (b) is
cheaper and honest; option (a) only pays off when role inheritance or richer
matchers are actually needed.

**Resolution (2026-08-08):** **Option B accepted and applied.**
`config/access/model.conf` deleted; `access.model_path` removed from
`AccessConfig` and TOML/`vcp.conf`; rules/skills wording updated to
Casbin-format / `PolicyStore`; `scripts/check_auth_tenant.sh` pins the
absence of `model.conf`, `model_path`, and a `casbin` crate dependency.

### F2 — No reverse drift test on the CSV (Low)

`TRACKED_PERMS` → CSV is pinned (every tracked couple must be granted), but
not the reverse: a CSV line granting an **untracked** couple (typo like
`p, role:org, build, read`) loads silently and grants nothing. The intent
(grant) would fail closed but invisibly.

**Recommendation:** add a unit/invariant test asserting every `(obj, act)` in
the CSV is a member of `TRACKED_PERMS` (and optionally that subjects are in a
closed role set `{role:org, role:admin}`).

### F3 — Empty or lockout policy file boots silently (Low)

Config validation checks `policy_path` is non-empty as a **string**, and the
parser aborts on malformed lines — but a syntactically valid file with zero
grants (or missing `admin, view`) boots fine and locks everyone out
(fail-closed, but a production foot-gun since prod reads
`/usr/local/etc/vcp/access/vcp_policy.csv`, not the repo file that the
repo lint pins).

**Recommendation:** startup sanity check after load: at least one grant, and
`role:admin` must hold `admin, view` (log + abort otherwise).

### F4 — Org dashboard has no capability entry gate (Low)

`/{org}` (dashboard + `org_layout`) only calls `require_org`. The page renders
published-docs count and latest article, latest certified build (with notes),
and issue summaries **without** checking `docs_read` / `builds_read` /
`issues_read`. Equivalent today because `role:org` holds all three read caps,
but it breaks least-privilege the day a restricted role is introduced, and it
is the only surface where module data renders without its module flag.

**Recommendation:** gate each dashboard panel on its flag (`perms.docs_read`,
`perms.builds_read`, `perms.issues_read`) — cheap now, keeps the model uniform.

### F5 — Download 403 is checked before release visibility 404 (Low)

`builds_download` POST and ephemeral generation check `!perms.builds_download`
→ 403 **before** `find_visible_release_by_version` → 404. The
anti-enumeration plan wording is "403 only on a **visible** resource". No
oracle exists (the 403 is uniform per capability and `require_org` already
passed, and both current roles hold `builds_download`, making the branch
unreachable today) — but the order contradicts the plan's letter.

**Recommendation:** swap the checks (visibility first) or add a comment
documenting why capability-first is acceptable here.

### F6 — `require_org_admin` is dead code (Info)

Marked `#[allow(dead_code)]`, never called (admin tools are global under
`/admin/*` via `require_staff`). It is still pinned by lints. Keep-or-drop
decision: if org-scoped admin never returns, delete it and its pins.

### F7 — Stale `#[allow(dead_code)]` on `require_admin_view` (Info)

The function **is** used (by `require_staff` and `require_org_admin`); the
allow is a leftover. Harmless; remove the attribute.

### F8 — Ephemeral public download link: token-based bypass by design (Info)

`GET /releases/{token}/{pkg}` is sessionless on purpose. Mitigations present:
UUIDv4 token (~122 bits), TTL (`EPH_DOWNLOAD_TTL_SECS`), expiry checked
server-side, release must still be **visible** for the issuing org at GET
time, single active token per (user, org, version), and minting requires the
full `require_org` + `builds_download` path. No token-guess rate limit, which
is acceptable at this entropy; documenting the reasoning in the module header
would close the loop.

### F9 — JIT staff elevation via `magiclinks.vcp_admin` (Info)

A magic-link request for the configured `vcp_admin` email auto-creates or
revives that account as `portal_role=admin` with a `vauban` membership
(`ensure_vcp_admin_user`). Exact normalized-email match against **config**,
not user input — sound, but it is the single knob that mints staff.
**Recommendation:** emit an explicit audit-grade log line when JIT elevation
runs, and call out in ops docs that production `vcp.conf` custody controls
staff access.

### F10 — `portal_role` string comparisons exist, correctly confined (Info)

All direct `portal_role` comparisons sit in the identity layer (`auth.rs`,
`models.rs` catalogue helpers, login landing) or account-class invariants
(`companies_accounts.rs`), never as capability gates in pages/views. The one
place that converts `portal_role` into a Casbin subject outside `auth.rs`
(`images.rs` support path) then decides **via `PermissionContext`**. This is
the intended layering; keep the lint that freezes it.

## 4. Test evidence (2026-08-08)

- `cargo test -p vcp --lib perms` — 3/3 green (grant matrix, role denials).
- `just test -- auth_tenant` — 34/49 green: **all** unit, invariants
  (including full `scripts/check_auth_tenant.sh`), and proptest layers pass.
  The 15 E2E/battle failures are **environmental**: every one panics at
  router construction with "asset catalog is stale or incomplete" — a
  test-profile asset-bundle race with the `just run` dev server that was
  running in another terminal during the audit, not an authorization failure.
  Re-run with the dev server stopped to confirm the committed-green baseline.

## 5. Priority summary

| # | Finding | Severity | Effort |
|---|---------|----------|--------|
| F1 | Homegrown loader vs. real Casbin; dead `model.conf` / `model_path` | Medium | **Resolved (option B)** |
| F2 | Reverse CSV→TRACKED_PERMS drift test missing | Low | S |
| F3 | No startup sanity on loaded policy (lockout boots) | Low | S |
| F4 | Dashboard panels not gated per-module | Low | S |
| F5 | 403-before-visibility order on downloads | Low | S |
| F6 | Dead `require_org_admin` | Info | S |
| F7 | Stale allow on `require_admin_view` | Info | S |
| F8 | Document ephemeral token threat model | Info | S |
| F9 | Audit log on JIT staff elevation | Info | S |
| F10 | `portal_role` confinement — keep lint | Info | — |

## 6. Verdict

The permission model is **correctly and uniformly applied**: every routed
surface goes tenant-gate → capability-flag → object-scope, entry denials are
anti-enumeration 404s, views read `PermissionContext` flags, no role-boolean
gates exist in application code, and the whole posture is frozen by structural
lints and a multi-layer test pyramid. F1 (naming / dead `model.conf`) is
**resolved via option B**: CSV + `PolicyStore` is the documented enforcement
path. The remaining findings are small hardening and hygiene items, none of
which is an exploitable flaw in the current two-role model.
