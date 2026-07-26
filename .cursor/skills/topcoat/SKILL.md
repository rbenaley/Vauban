---
name: topcoat
description: >-
  Durable knowledge of the Topcoat framework for VCP. Use when scaffolding,
  implementing pages/components/shards/procedures, sessions, cookies, routing,
  assets, Tailwind/UI, or when unsure how Topcoat works. Read before inventing
  Axum/Askama/HTMX patterns.
---

# Topcoat knowledge base (VCP)

Canonical upstream: [tokio-rs/topcoat](https://github.com/tokio-rs/topcoat).
Agent map of the repo: upstream `AGENTS.md`. User guides live under each
crate’s `docs/` (embedded into rustdoc).

This skill captures a study of Topcoat for the **Vauban Customer Portal**.
VCP product constraints that override framework capabilities are marked
**VCP**. Broader conventions live in the `web-stack` skill and the
`.cursor/rules/*.mdc` set.

**Last studied:** 2026-07-26 against upstream `main` (~workspace **0.4.0**,
edition **2024**, MSRV **1.95**). Re-check crates.io / GitHub before
scaffold if months have passed — the framework is early-stage.

---

## 1. What Topcoat is

- Batteries-included **server-rendered** Rust web framework (Tokio).
- Apps depend on the **facade** crate `topcoat` only. Internal crates
  (`topcoat-view`, `topcoat-router`, …) are implementation details.
- Priorities: simplicity and productivity; **safe Rust only**
  (`unsafe_code = deny` in the upstream workspace).
- Explicitly **early-stage / experimental** — expect breaking changes.
  Pin versions in VCP.

**VCP:** Internet CRUD portal over HTTPS request/response. Do **not**
enable the optional `websocket` feature. TLS 1.3 + post-quantum readiness
are VCP’s edge concern (`tls-post-quantum.mdc`), not provided by Topcoat.

---

## 2. Crate map (upstream)

| Crate | Role |
|-------|------|
| `topcoat` | Facade / re-exports |
| `topcoat-core` | `Error`/`Result`, `Cx`, app/request context, `#[memoize]` |
| `topcoat-view` | `view!`, `attributes!`, `class!`, `#[component]` |
| `topcoat-router` | `Router`, `#[page]`/`#[layout]`/`#[route]`, `module_router!`, tower/WS bridges |
| `topcoat-runtime` | Signals, `$(...)` / `expr!`, `#[procedure]`, `#[shard]`, browser script |
| `topcoat-asset` | `asset!`, `AssetBundle`, content-hashed URLs |
| `topcoat-cookie` | Cookie jar, `cookie!`, signed/private jars, `CookieStore<T>` |
| `topcoat-session` | BYO-storage sessions, token/hash model, `OriginLayer` |
| `topcoat-font` / `topcoat-icon` | Web fonts, Iconify |
| `topcoat-tailwind` | Standalone Tailwind CLI via build script |
| `topcoat-ui` | Registry for `topcoat ui` (copy components into the app) |
| `topcoat-htmx` / `topcoat-alpine-ajax` | Optional header helpers |
| `topcoat-cli` | `topcoat` binary: `dev`, `fmt`, `ui`, asset bundling |

Macro crates usually come as **trio**: runtime types + `grammar/` + `macro/`.

---

## 3. Features (facade)

**Default** includes roughly: `asset`, `compression`, `cookie`, `font`,
`icon`, `router`, `runtime`, `serve`, `session`, `view`, `discover`.

Notable optional: `tailwind`, `ui`, `htmx`, `alpine-ajax`, `tower`,
`multipart`, `websocket`, Fontsource/Iconify extras.

**VCP:** leave `websocket` off. Enable `tailwind` / `ui` when scaffolding UI.

---

## 4. Hello path

```rust
use topcoat::{
    Result,
    router::{Router, RouterBuilderDiscoverExt, page},
    view::{component, view},
};

#[tokio::main]
async fn main() {
    topcoat::start(Router::builder().discover().build()).await.unwrap();
}

#[page("/")]
async fn home() -> Result {
    view! {
        <!DOCTYPE html>
        <html>
            <head>
                <title>"Hello"</title>
                topcoat::dev::script()   // HMR with `topcoat dev`
            </head>
            <body>
                hello(name: "World")
            </body>
        </html>
    }
}

#[component]
async fn hello(name: &str) -> Result {
    view! { <h1>"Hello, " (name) "!"</h1> }
}
```

Day-to-day: `cargo install topcoat-cli` then `topcoat dev` (watch, rebuild,
rebundle). Override bind with `HOST` / `PORT`. Format macros with
`topcoat fmt`.

---

## 5. Views and components

- `view!`: HTML-like + Rust control flow (`if` / `for` / `match` / `let`),
  interpolation `(expr)`, conditional attributes.
- `#[component]`: async functions as components; props; optional child
  content; optional `cx: &Cx`.
- `attributes!` / `class!` / `props!`: attribute fragments and class lists.
- Components may be async and talk to the DB directly — no mandatory
  separate JSON API for HTML.

Upstream guides: `topcoat-view/macro/docs/view.md`, `component.md`, etc.

---

## 6. Routing

- Manual: register `#[page]`, `#[layout]`, `#[route]` on `Router::builder()`.
- Discover: `.discover()` + inventory (feature `discover`).
- Module router: derive URL tree from `src/app.rs` + `src/app/**`
  (kebab segments; `_prefix` layouts without a URL segment;
  `segment!` overrides).
- Path/query: `#[path_param]`, `#[query_params]`.
- Layouts nest by path prefix.
- Errors: router status helpers; `RouterErrorExt` (`ok_or_redirect`,
  `ok_or_unauthorized`, `ok_or_forbidden`, …).
- Tower: `TowerRoute` / `TowerLayer` behind `tower` feature — for
  **transport** concerns, not app auth.

**VCP:** prefer module-based routing + discover for the portal tree.

---

## 7. Request context — functions, not middlewares

Philosophy (upstream `functions_not_middlewares.md`):

- Prefer short `async fn foo(cx: &Cx)` helpers over middleware that
  stuffs `User` into extensions, and over extractors that force
  prop-drilling through every component.
- Use `#[memoize]` so repeated `require_auth` / DB lookups in one request
  dedupe.
- `app_context::<T>(cx)` for long-lived values registered with
  `.app_context(value)` (DB pool, cookie `Key`, …).
- Reach for layers only for compression, tracing, low-level HTTP.

**VCP pattern:**

```text
current_user(cx) -> require_auth(cx) -> require_org(cx) / require_perms(cx)
browser_tz(cx)   // vcp_tz cookie
```

Casbin gates: `casbin-permissions.mdc`. Tenant isolation: `portal-security.mdc`.

---

## 8. Cookies

- Install: `.cookies()` on the router.
- `cookies(cx)` → request jar; `get` / `add` / `remove`; `Set-Cookie`
  flushed at end of request.
- `cookie!` macro for attributes; combinators `default_*` / `override_*`
  for Secure, HttpOnly, SameSite, Path, Domain, MaxAge.
- Name prefixes: `prefix_host` (`__Host-`), `prefix_secure` (`__Secure-`).
- **Signed** jar: tamper-evident, client-readable.
- **Private** jar: AES-256-GCM, confidential + tamper-evident.
- Register `cookie::Key` in app context once; use `signed_cookies(cx)` /
  `private_cookies(cx)`. Regenerating the key every boot invalidates
  all existing cookies.
- `CookieStore<T>`: JSON-typed values; nothing written until `commit()`.

Idiom: app-local `fn cookies(cx) -> impl Cookies` with security defaults.

---

## 9. Sessions (critical for VCP auth)

Upstream `session.md` — mechanics only; **you own storage**.

Model:

1. Client holds a 32-byte random **token** (default hardened cookie:
   `__Host-`, `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`).
2. Server persists **SHA-256 hash** (`TokenHash`) + `expires_at` + user
   binding — never the raw token.
3. API: `session::start` (login, anti-fixation), `token_hash`,
   `stop` (logout), `refresh` (sliding expiry), `rotate` (privilege change).

Setup:

```rust
Router::builder()
    .cookies()
    .sessions(SessionConfig::default())
    // ...
```

Resolve user: `token_hash(cx)` → lookup in your DB → `None` if missing
or expired. Guard with `ok_or_redirect("/login")` / unauthorized helpers.

### CSRF / OriginLayer

`.sessions()` registers **`OriginLayer`**:

- For methods other than GET/HEAD/OPTIONS, requires
  `Sec-Fetch-Site: same-origin|none`, or matching `Origin` host for older
  browsers.
- Requests with neither header pass (non-browser clients).
- Trust extra origins via `SessionConfig::builder().trust_origin(...)`.
- `dangerous_disable_origin_verification` only with a replacement CSRF design.

**VCP:** keep OriginLayer on; mutations on POST (etc.); never
state-changing GET. Aligns with `portal-security.mdc`.

Custom `TokenStore` can put the token in `Authorization: Bearer` for M2M
instead of a cookie.

---

## 10. Runtime (reactivity) — experimental

Upstream warns: **highly experimental**, limited expression vocabulary,
breaking changes expected.

Concepts:

- Include `topcoat::runtime::script()` in `<head>`; load
  `AssetBundle` on the router.
- `$(...)` / `expr!`: dual Rust + JS expression; server evaluates for SSR,
  browser re-runs when signals change.
- `signal name = …;` in `view!`: browser state.
- `@click` / `@input` / …: event handlers (closures or raw JS strings).
- `:attr=$(...)`: bind attributes kept in sync.
- **`#[procedure]`**: async server fn callable from the browser (HTTP).
  **Arguments are attacker-controlled — re-auth and re-authorize.**
- **`#[shard]`**: component re-rendered on the server when `$(...)`
  args change; HTML swapped in. **Same trust boundary as procedures.**

**VCP:** fine for progressive UI (toggles, search-as-you-type). Prefer
boring PRG forms for critical auth/billing mutations. Never treat shard /
procedure args as trusted org/entitlement claims.

---

## 11. Assets, Tailwind, UI

- `const X: Asset = asset!("./file.png");` → content-hashed URL; serve via
  bundle from `topcoat` CLI / `AssetBundle::load()`.
- Tailwind: feature `tailwind`, `topcoat::tailwind::stylesheet!()` —
  standalone CLI, no Node required for that path.
- `topcoat ui`: copy editable components into the project (shadcn-like).
- Fonts / icons: `font!`, Iconify integration.

**VCP:** brand toward `vauban.sh`, not bastion dark admin chrome. Responsive
rules: `responsive-ui.mdc`. Design workflow: `designing-beautiful-websites`.

---

## 12. Optional integrations

| Feature | Use when |
|---------|----------|
| `htmx` / `alpine-ajax` | Partial HTML swaps via those libs’ headers |
| `tower` | Bridge tower services/layers |
| `websocket` | **VCP: do not enable** |

### ORM (VCP locked): Toasty + PostgreSQL

- **ORM:** [Toasty](https://github.com/tokio-rs/toasty) — async, Tokio
  ecosystem; Topcoat example: `examples/toasty-todo` (SQLite there;
  **VCP uses the PostgreSQL driver**).
- **Guide:** [Toasty guide](https://tokio-rs.github.io/toasty/nightly/guide/).
- **Topcoat roadmap** mentions deeper Toasty integration (forms /
  validations); do not wait for it — wire Toasty via `app_context` +
  `db(cx)` today (see `web-stack`).
- Pin exact **0.x** versions; expect churn.
- Escape hatch: narrow `sqlx` only when Toasty cannot express a query —
  not a second data model (`web-stack` § Database / ORM).

Scaffolded in the `vcp` binary: `User`, `AuthSession` (token hash hex +
expiry), `Organization`, `Membership`, plus stub `DocArticle` /
`Release` / `Issue`. Routes follow `/{org}/…` and `/{org}/admin/…`
(see `web-stack`).

---

## 13. Tooling cheat sheet

| Command | Purpose |
|---------|---------|
| `topcoat dev` | Build, bundle, serve, watch, HMR |
| `topcoat fmt` | Format `view!` and other macro bodies |
| `topcoat ui …` | Init theme / add / update / remove UI components |
| `cargo run` | Serve without the full CLI workflow |

Validation for VCP still follows `dev-validation-cycle.mdc` /
`quality-assurance` (`cargo fmt`, clippy `-D warnings`, tests).

---

## 14. Anti-patterns (do not import from bastion)

| Avoid | Prefer |
|-------|--------|
| Askama templates | `view!` |
| Axum extractors as the auth model | `cx` functions + memoize |
| HTMX+Alpine as the default stack | Topcoat runtime / shards / PRG |
| Capsicum `include_bytes!` static registry | `asset!` pipeline |
| Bastion WebSocket dashboards | HTTP CRUD only |
| Trusting procedure/shard args | Re-check session + Casbin + tenant |
| Assuming Topcoat does TLS | Edge TLS 1.3 / PQ (`tls-post-quantum.mdc`) |

---

## 15. Upstream doc index (refresh when needed)

Getting started / router / context / cookies / sessions / runtime /
assets / Tailwind / UI / htmx / alpine-ajax — under
`crates/topcoat/docs/` on GitHub.

Module router: `crates/topcoat-router/docs/module_router.md`.

Macros: `crates/topcoat-*/macro/docs/`.

When behavior is unclear, **fetch the current upstream guide** rather
than guessing from memory of older releases.

---

## 16. Related VCP artifacts

| Artifact | Role |
|----------|------|
| `web-stack` skill | VCP conventions (incl. Toasty + Postgres) |
| `casbin-permissions.mdc` | AuthZ gates |
| `portal-security.mdc` | Tenancy, CSRF, secrets |
| `tls-post-quantum.mdc` | HTTPS edge / PQ |
| `timezone-localization.mdc` | `vcp_tz` |
| `vcp-test-pyramid.mdc` | Behavioral tests |
| `quality-assurance` skill | fmt / clippy / tests |
