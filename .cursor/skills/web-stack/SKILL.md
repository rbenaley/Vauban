---
name: web-stack
description: >-
  Topcoat-based full-stack conventions for VCP. Use when scaffolding,
  adding pages/components/shards, routing, assets, Tailwind, sessions,
  or choosing how to implement a web feature in this portal.
---

# VCP web stack (Topcoat)

Framework knowledge (crate map, sessions, runtime, anti-patterns) lives
in the **`topcoat` skill** — read it when unsure. This skill is VCP’s
product conventions on top of that base.

Upstream orientation (keep in sync with `topcoat` skill):

- [Announcing Topcoat](https://tokio.rs/blog/2026-07-22-announcing-topcoat)
- [Toasty 0.6.0 — what is new?](https://tokio.rs/blog/2026-05-15-announcing-toasty-0-6-0)
  (VCP pins **toasty 0.9** — confirm APIs against `Cargo.toml` / lock)

VCP is a **Topcoat** application ([tokio-rs/topcoat](https://github.com/tokio-rs/topcoat)).
Depend on the facade crate `topcoat` only (internal crates are
implementation details). Workspace status as of study: **~0.4.x**,
edition **2024**, MSRV **1.95**, `unsafe_code = deny`. Early-stage —
expect breaking changes; pin versions. Topcoat and Axum are
**complementary** (Topcoat for the HTML portal; Axum only if a raw
HTTP API seam is explicitly needed — do not rebuild the portal in
Axum+Askama).

**Product shape:** Internet CRUD portal over HTTPS request/response.
Do **not** enable Topcoat’s optional `websocket` feature. Prefer pages
+ forms + PRG; use shards / procedures for in-page updates when needed.

**Wire security:** TLS 1.3-only public edge, rustls-preferred, hybrid
post-quantum readiness — see `tls-post-quantum.mdc` (TLS is **not**
provided by Topcoat; terminate in-process or at the reverse proxy).

This is **not** the bastion (`../Vauban`: Axum + Askama + HTMX + Alpine).
Do not import Capsicum, mTLS IPC, WebSocket viewers, or bastion
static-asset embedding assumptions unless explicitly requested.

## Core stack

| Layer | Choice |
|-------|--------|
| Framework | Topcoat facade (`topcoat::start` / `Router`) |
| Templates / UI | `view!`, `#[component]`, `#[page]` / `#[layout]` / `#[route]` |
| Routing | Prefer `.discover()` + module tree (`module_router!`) |
| Reactivity | Optional `topcoat-runtime`: signals, `$(...)`, `@` / `:` — **experimental / limited vocabulary** |
| Server partials | `#[shard]` (HTTP re-render; **args are untrusted**) |
| Server actions | `#[procedure]` (HTTP RPC; **args are untrusted**) |
| Styling | `tailwind` + `styles.css` Concept `@theme` / `vb-*` (not Topcoat UI) |
| Assets | `stylesheet!()` + `AssetBundle::load()`; Fontsource via `font-fontsource` |
| Cookies | `.cookies()`; signed / private (AES-256-GCM) jars; app `Key` in app context |
| Sessions | `.sessions(SessionConfig)` — BYO storage of **SHA-256 token hash** + expiry |
| CSRF | Session `OriginLayer` (Sec-Fetch-Site / Origin) — keep mutations on non-GET |
| AuthZ | Casbin `PermissionContext` via `cx` functions — see `casbin-permissions.mdc` |
| Dates in HTML | `vcp_tz` cookie + `format_local*` — see `timezone-localization.mdc` |
| ORM | **Toasty** ([tokio-rs/toasty](https://github.com/tokio-rs/toasty)) |
| Database | **PostgreSQL** (dev / staging / prod). SQLite is not the default |
| Tooling | `just run` (HTTPS), `topcoat dev` (HMR), `topcoat fmt`, `just bundle`; root layout includes `runtime::script()` + `dev::script()` |

## Database / ORM (Toasty + PostgreSQL)

**Locked choice.** Do not introduce Diesel as a parallel stack. Do not
copy bastion Diesel schemas or migrations from `../Vauban`.

Toasty is an async ORM (ease-of-use first; SQL + NoSQL). VCP uses the
**PostgreSQL** driver only. Topcoat’s roadmap mentions tighter Toasty
integration later — wire `app_context` + `db(cx)` today.

### Pinning

- Toasty is **0.x** — expect breaking changes (0.4→0.6 shipped quickly;
  VCP currently pins **0.9.0**). Pin **exact** versions in `Cargo.toml`
  / `Cargo.lock`; bump deliberately after reading the changelog. Do not
  track git `main` ad hoc.
- Enable the **PostgreSQL** driver feature (not SQLite) for the app
  default. See Topcoat’s `examples/toasty-todo` for a minimal wiring
  pattern (that example uses SQLite — VCP uses Postgres instead).
- Guide: [Toasty guide](https://tokio-rs.github.io/toasty/nightly/guide/).
- Orientation: [Toasty 0.6 announcement](https://tokio.rs/blog/2026-05-15-announcing-toasty-0-6-0)
  (deferred / select / `Vec` scalars landed by 0.6; verify against 0.9).

### Access pattern

```text
Router .app_context(db)
  -> fn db(cx: &Cx) -> DbHandle
  -> models / queries in pages, components, shards, procedures
```

- Register the Toasty DB / pool on the router with `.app_context(...)`.
- Expose `fn db(cx: &Cx) -> …` (clone or pool handle). Prefer
  `#[memoize]` for hot per-request lookups.
- Models: `#[derive(toasty::Model)]` under `src/models/` (or
  `src/db/models/`). Keep a thin `src/db.rs` (or `src/db/mod.rs`) for
  connect / schema helpers — not a heavy repository layer unless needed.
- Prefer **locality of behavior**: components/pages fetch what they need
  via `cx` helpers rather than always prop-drilling full graphs from
  parents (`topcoat` skill §7).
- Connection URL: `[database].url` from TOML under `config/` (see
  `src/config.rs`); production uses `config/vcp.conf` only;
  never commit real credentials.
- Automated tests: `vcp_test` via `just test` / `just validate`
  (`ensure-vcp-test`); URL in `config/testing.toml`.

### Query capabilities (prefer before inventing raw SQL)

Capabilities from Toasty ≥0.6 (confirm names against the locked crate):

| Capability | Shape | When |
|------------|-------|------|
| Deferred fields | `#[deferred] body: Deferred<T>` + `.include(Model::fields().body())` | Omit large columns on list/index queries; load on demand |
| Field `select()` | `.select(Model::fields().title())` → scalars / tuples, **not** full model | Projections, lightweight lists |
| `Vec` of scalars | e.g. `tags: Vec<String>` | Postgres **arrays** (other SQL → JSON; DynamoDB lists) |
| Collection updates | `.tags(toasty::stmt::extend([...]))` | Append / mutate without blind full rewrite |
| Array filters | `.tags().intersects([...])` (and related) | Tag / set membership |

Also available upstream when needed: richer query expressions, db-native
enums, optimistic version control, TLS for DB clients. Document/JSON(B)
storage is on Toasty’s roadmap — do **not** invent a parallel document
layer in VCP until Toasty exposes it cleanly.

### Sessions and tenancy

- Persist Topcoat session rows as **`TokenHash` + `expires_at` + user
  id** (and any VCP extras). Never store or log the raw session token.
- Every org-scoped query MUST filter on the active organization resolved
  from membership — Casbin alone is not enough (`portal-security.mdc`,
  `casbin-permissions.mdc`).

### Escape hatch

If Toasty cannot express a query cleanly **after** checking deferred /
`select` / collection APIs, a **narrow** `sqlx` (or equivalent) module
is allowed for that seam only. Do **not** grow a second full data model
or duplicate entities in both ORMs. Document the escape in a short
comment or module docs at the call site.

### App scaffold checklist (when creating the binary)

1. `cargo add toasty` with the PostgreSQL driver feature; pin versions.
2. Wire pool into router `.app_context`; add `db(cx)` (+ memoize as needed).
3. First models: `User`, session record (`TokenHash`), `Organization`,
   membership — enough for login + tenant.
4. Schema via Toasty migrations (`Toasty.toml`, `toasty/`, binary
   `vcp-cli`): edit models → `just db-migrate-generate NAME=…` → review
   SQL → `just db-migrate`. `db::connect` applies pending migrations.
   Do **not** use `push_schema` for the app DB. URL from TOML
   (`VCP_ENVIRONMENT=development` for local layering); no secrets in git.
5. CI: Postgres service (or testcontainers) + focused auth/tenant tests
   per `vcp-test-pyramid.mdc`.

## Routing and structure

Prefer Topcoat **`module_router!()`** with the mockup IA:

```text
src/
|-- main.rs
|-- db.rs                  -> Toasty connect / seed
|-- models/                -> toasty::Model types
|-- auth.rs                -> current_user / require_* helpers
|-- perms.rs               -> PermissionContext + Casbin
|-- nav.rs                 -> NavSection + crumb from URI
|-- fonts.rs               -> Fontsource Hanken / JetBrains
|-- app.rs                 -> root #[layout], module_router!, assets
`-- app/
    |-- _components/       -> #[component] vb_* (group, no URL)
    |-- login.rs           -> login #[layout] + /login
    `-- org.rs             -> org #[layout] (rail/topbar) + /{org}
        `-- org/
            |-- docs.rs
            |-- builds.rs
            |-- issues.rs
            |-- account.rs
            `-- admin.rs   -> /{org}/admin/* (admin_view gate)
```

`styles.css` + `Topcoat.toml` at package root. Pages return **bodies only**;
layouts own chrome. Deep-link routes for docs/builds/issues stay shareable;
runtime signals enhance in-page dismiss/collapse/tabs only.

### Shell conventions (Concept mockups)

- Dark left rail, light content, accent teal `#117a6b` (`@theme` + `vb-*`).
- Breadcrumb: `vauban://portal / {org} / {section}` via `vb_topbar`.
- Client rail: Home, Docs, Builds, Issues; Admin rail: Docs, Rel., Orgs.
- Org initials control links to `/{org}/account`.
- **Do not** vendor `topcoat ui` for the portal shell.

- HTML pages for humans; JSON under `/api/...` only for M2M / webhooks.
- HTML forms MUST NOT post to machine JSON APIs as a substitute for
  page handlers.
- Prefer PRG (Post-Redirect-Get) for full form submissions; use shards /
  procedures for in-page updates that truly need them.

## Rendering principles

- **Server-first**: components may be async and talk to the DB directly.
- **No parallel SPA**: do not introduce React/Vue/Svelte for the portal
  shell unless the user explicitly asks.
- Prefer Concept `#[component]` fragments under `app/_components`. Topcoat
  UI registry vendoring is optional/out of scope — align with Concept /
  `vauban.sh`, not bastion dark admin chrome or shadcn defaults.
- Accessibility: visible focus, labels, sensible semantics; WCAG 2.1 AA
  as the bar for interactive flows.
- Responsive: follow `responsive-ui.mdc` (mobile-first, 375 px).

## Overview / home surfaces

If VCP gains a customer “home” or status overview, keep it a **radar**:
read-only situational awareness. Mutating actions (invite, buy, revoke,
download with side effects) belong on dedicated task pages — not as a
wall of buttons on the overview. Refresh via normal HTTP (reload, PRG,
shards), never via a WebSocket channel. Dates and tenant scope follow
`timezone-localization.mdc` and `casbin-permissions.mdc`.

## Request-scoped concerns

Topcoat’s guiding principle: **locality of behavior** — keep fetch,
auth, and rendering close
([announcement](https://tokio.rs/blog/2026-07-22-announcing-topcoat),
[functions_not_middlewares](https://github.com/tokio-rs/topcoat/blob/main/crates/topcoat/docs/functions_not_middlewares.md)).

- Prefer `async fn foo(cx: &Cx)` helpers over middleware that stuffs
  `User` into extensions, and over extractors that force prop-drilling.
- Components may load their own data; use `#[memoize]` (request-scoped)
  so repeated lookups for the same key dedupe within one request.
- Protect data **inside** the page/component via `require_*` — do not
  rely on a distant middleware “having run”.

Typical helpers (names illustrative):

- `current_user(cx)` — `session::token_hash` → storage lookup
- `require_auth(cx)` — anonymous → unauthorized / redirect to login
- `require_perms(cx)` — Casbin `PermissionContext` (memoize per request)
- `require_org(cx)` — active tenant + membership
- `browser_tz(cx)` — `vcp_tz` → `chrono_tz::Tz`

Fail closed when context is missing. See `portal-security.mdc` and
`casbin-permissions.mdc`.

Use Tower layers (`tower` feature) only for true transport concerns
(compression, tracing) — not for “load user into extensions”.

## Sessions, CSRF, and cookies

From Topcoat session/cookie guides:

- Default session cookie is hardened (`__Host-`, `Secure`, `HttpOnly`,
  `SameSite=Lax`). Persist **only** `TokenHash` + `expires_at`, never
  the raw token.
- `.sessions()` installs an **`OriginLayer`**: non-safe methods must
  present same-origin `Sec-Fetch-Site` (or matching `Origin`). Trust
  extra origins explicitly (e.g. OAuth `form_post`); do not disable
  verification without a replacement CSRF design.
- Keep state-changing routes on `POST` (etc.); a state-changing `GET`
  bypasses the OriginLayer by design.
- App cookie defaults: helper wrapping `cookies(cx)` with Secure /
  HttpOnly / SameSite / Path; use signed or private jars when values
  must be tamper-proof or confidential.
- Never log raw session tokens, license keys, or payment payloads.

## Procedures and shards (trust boundary)

Topcoat reactivity is **not WASM**: signals/`$(...)` can run
client-only; `#[shard]` re-renders HTML on the server when bound args
change; `#[procedure]` is HTTP RPC. Details: `topcoat` skill §10.

`#[shard]` and `#[procedure]` expose HTTP endpoints. Treat arguments as
**attacker-controlled**: re-check auth, tenant, and Casbin inside the
body; do not trust client-supplied org ids or entitlement claims.
Prefer PRG forms for sensitive mutations; reserve shards for progressive
UI (filters, expands) that still re-authorize.

## What not to copy from the bastion web skill

| Bastion pattern | VCP instead |
|-----------------|-------------|
| Askama + HTMX + Alpine as the default UI kit | Topcoat `view!` + signals / shards |
| `include_bytes!` static registry for Capsicum | Topcoat `asset!` pipeline |
| gRPC mTLS / proxy / WebSocket viewers | Out of scope |
| Bastion Casbin resource names | VCP catalogue only |
| Bastion Diesel schemas / migrations | Toasty models + Postgres (VCP-owned) |
| TLS 1.3 + hybrid PQ (rustls) | **Keep** — same bar (`tls-post-quantum.mdc`) |

htmx / Alpine AJAX helpers exist in Topcoat for optional partial swaps;
use them only when shards/procedures are a worse fit — do not rebuild
the bastion dashboard stack by habit. Do not add WebSockets “for live
updates”; refresh via navigation, form PRG, or shards.

## Testing and validation

Behavioral changes follow `vcp-test-pyramid.mdc` and the
`quality-assurance` skill: fmt → lint (warnings as errors) → focused
tests including denial paths → widen.

Diagnostic commands: prefix with `rtk` (`rtk-proxy.mdc`).

## Checklist for a new surface

- [ ] Page / layout / shard placed in the module tree intentionally
- [ ] Auth + Casbin + tenant checks (fail closed)
- [ ] Org-scoped DB queries filter on active tenant
- [ ] Forms: CSRF + validation + PRG or documented shard/procedure
- [ ] Dates localized via `format_local*` when shown in HTML
- [ ] No secrets in logs; no cross-tenant leakage in errors
- [ ] Pyramid layers listed for the change
- [ ] Brand / responsive pass for customer-facing UI
