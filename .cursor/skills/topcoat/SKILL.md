---
name: topcoat
description: >-
  Durable knowledge of the Topcoat framework for VCP. Use when scaffolding,
  implementing pages/components/shards/procedures, signals, @click/:bind,
  sessions, cookies, routing, assets, Tailwind/UI, or when unsure how Topcoat
  works. Read before inventing Axum/Askama/HTMX or first-party UI JS.
---

# Topcoat knowledge base (VCP)

Canonical upstream: [tokio-rs/topcoat](https://github.com/tokio-rs/topcoat).
Agent map of the repo: upstream `AGENTS.md`. User guides live under each
crate’s `docs/` (embedded into rustdoc).

Announcement / orientation (read when refreshing mental model):

- [Announcing Topcoat](https://tokio.rs/blog/2026-07-22-announcing-topcoat)
  (2026-07-22, Carl Lerche & Julien Scholz)
- Sibling ORM: [Toasty 0.6.0 — what is new?](https://tokio.rs/blog/2026-05-15-announcing-toasty-0-6-0)
  (field select / deferred / `Vec` scalars; VCP pins a newer 0.x — see
  `Cargo.toml`)

This skill captures a study of Topcoat for the **Vauban Customer Portal**.
VCP product constraints that override framework capabilities are marked
**VCP**. Broader conventions live in the `web-stack` skill and the
`.cursor/rules/*.mdc` set.

**Last studied:** 2026-07-28 against upstream ~**0.4.0** (edition **2024**,
MSRV **1.95**) plus VCP builds ephemeral UI (signals, `@click` bind
contract). Re-check crates.io / GitHub before scaffold if months have
passed — the framework is early-stage.

Community: Tokio Discord `#topcoat` (and `#toasty` for the ORM).

---

## 1. What Topcoat is

- Modular, batteries-included **server-rendered** Rust web framework
  (Tokio). Reactivity is *not* WASM: the server renders HTML, and the
  runtime attaches **reactive instructions as metadata** (same *idea*
  family as HTMX — snippets + instructions — with a Rust→JS expression
  subset instead of a separate client app).
- Apps depend on the **facade** crate `topcoat` only. Internal crates
  (`topcoat-view`, `topcoat-router`, …) are implementation details.
- Priorities: simplicity and productivity; **safe Rust only**
  (`unsafe_code = deny` in the upstream workspace).
- Explicitly **early-stage / experimental** — expect breaking changes.
  Pin versions in VCP.
- Ecosystem story (upstream): **Toasty** (ORM, ready since 2026-04) then
  **Topcoat** (web). Roadmap mentions tighter Toasty integration,
  validations, email — wire today’s APIs; do not wait for future sugar.

### Topcoat vs Axum (upstream guidance)

| | Topcoat | Axum |
|---|---------|------|
| Role | Full-stack HTML app (pages, layouts, assets, sessions, light reactivity) | Lower-level HTTP router / APIs |
| Overlap | Many apps will use **both** | Prefer Axum when you only need raw HTTP endpoints |
| Do not | Rebuild a Topcoat-shaped portal in Axum+Askama “for familiarity” | Assume Axum replaces Topcoat’s UI stack |

**VCP:** Internet CRUD portal over HTTPS request/response. Do **not**
enable the optional `websocket` feature. TLS 1.3 + post-quantum readiness
are VCP’s edge concern (`tls-post-quantum.mdc`), not provided by Topcoat.
Custom serve path: `src/tls/serve.rs` (not `topcoat::start`).

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

### Redirects (prefer Topcoat helpers)

**Always prefer** the idiomatic Topcoat redirect helpers over hand-rolled
`StatusCode` + `Location` responses:

| Helper | Status | Use when |
|--------|--------|----------|
| `see_other(uri)` | **303** | Successful mutation → navigate with GET (**PRG**). Return `Ok(see_other(...))` / `Result<SeeOther>`. |
| `redirect(uri)` | **307** | Temporary redirect; **preserves** method. Prefer for short-lived “go there instead” from a handler (`Err(redirect(...).into())`). |
| `redirect_permanent(uri)` | **308** | Permanent URL move / canonicalization; **preserves** method. Prefer for trailing-slash strip, renamed routes, legacy path aliases. |

Rules:

- Do **not** invent `301` / `302` / raw `Response::builder().status(...).header(LOCATION, …)` when one of the three helpers fits.
- `ok_or_redirect("/login")` is fine for auth gates (uses the temporary redirect path).
- Canonical trailing-slash (and similar wide URL fixes): root `#[layer]` + `redirect_permanent` + pure path helper — see `src/http_canonical.rs` and `references/RUNTIME.md`.
- Open redirects: only allow origin-relative `Location` values you control; never bounce to an untrusted query param.

Detail and PRG notes: `references/RUNTIME.md` § Redirects.

---

## 7. Request context — locality of behavior

Guiding principle from the [Topcoat announcement](https://tokio.rs/blog/2026-07-22-announcing-topcoat)
and upstream `functions_not_middlewares.md`:

**Locality of behavior** — keep data fetching, auth, and rendering close
together. Humans and AI reason better over small regions of code.

- Prefer short `async fn foo(cx: &Cx)` helpers over middleware that
  stuffs `User` into extensions, and over extractors that force
  prop-drilling through every component.
- Let components **fetch their own data** instead of always receiving
  preloaded structs from parents (compose with `cx`).
- Use `#[memoize]` (request-scoped, React `cache`-like) so repeated
  `require_auth` / DB lookups in one request dedupe when several
  components ask for the same key.
- Protect data **inside** the component / page via helpers
  (`require_auth`, `require_org`, `require_perms`) rather than hoping a
  distant middleware ran — fail closed with redirect / 403 / 404.
- `app_context::<T>(cx)` for long-lived values registered with
  `.app_context(value)` (DB pool, cookie `Key`, …).
- Reach for layers only for compression, tracing, low-level HTTP —
  not app authZ.

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
breaking changes expected. **VCP does not** adopt HTMX / Alpine as the
default. Deep playbook: [`references/RUNTIME.md`](references/RUNTIME.md).

### Layers

| Layer | Where | VCP use |
|-------|-------|---------|
| **Signals + `$(...)` / `@` / `:`** | Browser | Tabs, countdown, show/hide, copy affordances |
| **`#[shard]`** | Server HTML swap | Live search / filtered lists needing DB |
| **`#[procedure]`** | Server RPC | Imperative actions (args untrusted) |
| **POST + PRG** | Full navigation | Auth, mint/revoke tokens, admin mutations |

**VCP split:** mint entitlements / tokens **server-side** (POST/PRG + DB).
Use Topcoat signals only for **ephemeral UI** after SSR. Do **not** add
first-party `assets/vcp_*.js` for toggles the runtime can express.

### Non-negotiable: `@click` bind contract (0.4)

Runtime attaches handlers as:

```js
s = new Function("cx", "return " + attrValue)(cx);
el.addEventListener(type, e => s(wrappedEvent));
```

So the attribute must **evaluate to a function**. Statement forms run at
**bind / scan time** and can throw — aborting the TreeWalker so **later
handlers on the page never attach**.

| Form | Result |
|------|--------|
| `@click=$(|_e| signal.set(…))` | OK (`$()` → function) |
| `@click=$(|e: Event| { e.prevent_default(); … })` | OK (prefer typed `Event`) |
| `@click="(e) => { … }"` / `@click="() => { … }"` | OK (raw JS **function**) |
| `@click="navigator.clipboard…; this.…"` | **FORBIDDEN** — runs at bind, breaks siblings |

Clipboard / DOM that `$()` cannot express: raw **function** using the
Topcoat event wrapper, e.g.
`(e) => { const el = e.current_target.inner; … }`.
Do not rely on `this` as the element.

CI helper: `tests/integration_tests/common/topcoat_click.rs`
(`assert_topcoat_click_handlers_are_functions`). Real click→DOM stays in
the smoke runbook (no headless browser in the pyramid).

### Patterns that work in VCP

- **Show/hide:** `:style=$(if live.get() { "" } else { "display:none" })`
  (proven). Prefer this over fragile `:class` when toggling visibility.
- **Bool / number signals:** `signal x = false;` / `f64` for countdown;
  client `if` uses `.dehydrate()` under the hood.
- **Ticks:** `@animationiteration=$(|_e| { … set … })` + tiny CSS
  `animation` (see `.vb-eph-tick`).
- **Tabs without navigation:** one `signal use_curl = false` +
  `@click=$(|_e| use_curl.set(true/false))` + reactive cmd text /
  `:data-copy` — never `?tool=` round-trips.
- **Config in handlers:** put `Arc<Config>` in `app_context`; read via
  `auth::config(cx)` (absolute URLs → `primary_public_origin()`).
- **`topcoat fmt`:** 0.4 panics on `signal` decls — `just fmt` skips
  those files (`Justfile` `topcoat-fmt`).

### Mechanics checklist

- `topcoat::runtime::script()` in root layout + `AssetBundle` on router
  (`just bundle` / `just run`).
- `$(...)`: dual Rust + JS; text nodes skip first DOM patch (SSR text
  stays until the signal changes).
- Scan order is document order: an early throwing `@click` kills later
  binds on the same page.
- Shard / procedure args: **re-auth + re-authorize every time.**


## 11. Assets, Tailwind, UI

- `const X: Asset = asset!("./file.png");` → content-hashed URL; serve via
  bundle from `topcoat` CLI / `AssetBundle::load()`.
- Tailwind: feature `tailwind`, `topcoat::tailwind::stylesheet!()` —
  standalone CLI, no Node required for that path. VCP input CSS is
  `styles.css` (`@import "tailwindcss"`, `@source`, Concept `@theme`).
- Fonts: feature `font-fontsource` + `fontsource_font!` (see `src/fonts.rs`).
- Icons: Iconify sets via `iconify::include!("…")` when needed (optional).
- `topcoat ui`: shadcn-inspired **copy-into-your-tree** Tailwind components
  (`topcoat ui …`). **Optional / out of scope for VCP** — keep Concept
  `vb-*` under `src/app/_components/`; do not vendor Topcoat UI defaults.

**VCP required idioms**

| Idiom | Where |
|-------|--------|
| `#[layout]` + `Slot` | Root (`app.rs`), login splash, org chrome |
| `#[component]` | `app/_components/*` (rail, topbar, modal, chips, badges) |
| `stylesheet!()` + `runtime::script()` + `dev::script()` | Root layout `<head>` |
| `AssetBundle::load()` | Fail closed in production; warn + empty only in dev/test |
| `just bundle` / `topcoat asset bundle` | After build so CSS/runtime assets resolve |

**VCP:** brand toward Concept / `vauban.sh`, not bastion dark admin chrome
or Topcoat UI purple defaults. Responsive: `responsive-ui.mdc`.

---

## 12. Optional integrations

| Feature | Use when |
|---------|----------|
| `htmx` / `alpine-ajax` | Partial HTML swaps via those libs’ headers |
| `tower` | Bridge tower services/layers |
| `websocket` | **VCP: do not enable** |

### ORM (VCP locked): Toasty + PostgreSQL

- **ORM:** [Toasty](https://github.com/tokio-rs/toasty) — async ORM,
  ease-of-use first; SQL + NoSQL (DynamoDB today on NoSQL). Topcoat
  example: `examples/toasty-todo` (SQLite there; **VCP uses PostgreSQL**).
- **Guide:** [Toasty guide](https://tokio-rs.github.io/toasty/nightly/guide/).
- Orientation: [Toasty 0.6 announcement](https://tokio.rs/blog/2026-05-15-announcing-toasty-0-6-0)
  (capabilities below landed by 0.6; VCP pins a newer 0.x in
  `Cargo.toml` — confirm APIs against the locked version).
- **Topcoat roadmap** mentions deeper Toasty integration (forms /
  validations); do not wait — wire via `app_context` + `db(cx)` today
  (`web-stack`).
- Pin exact **0.x** versions; expect churn (0.4→0.6 shipped quickly).
- Escape hatch: narrow `sqlx` only when Toasty cannot express a query —
  not a second data model (`web-stack` § Database / ORM).

**Useful Toasty capabilities (prefer before inventing raw SQL):**

| Capability | Shape | When |
|------------|-------|------|
| Deferred fields | `#[deferred] body: Deferred<String>` + `.include(Model::fields().body())` | Omit large columns on list queries; load on demand |
| Field `select()` | `.select(Model::fields().title())` → scalars / tuples, **not** full model | Index pages, projections |
| `Vec` of scalars | e.g. `tags: Vec<String>` | Postgres **arrays**; other SQL → JSON; DynamoDB lists |
| Collection updates | `.tags(toasty::stmt::extend([...]))` | Append / mutate without rewriting whole vec blindly |
| Array filters | `.tags().intersects([...])` (and related) | Tag / set membership queries |

Also called out upstream (use when needed): richer query expressions,
db-native enums, optimistic version control, TLS for DB clients.
Document/JSON(B)-style storage is on the Toasty roadmap — do not invent
a parallel document layer in VCP until Toasty exposes it.

Scaffolded in the `vcp` binary: `User`, `AuthSession` (token hash hex +
expiry), `Organization`, `Membership`, plus stub `DocArticle` /
`Release` / `Issue`. Client routes follow `/{org}/…`; staff tools live
under `/admin/…` (see `web-stack`).

---

## 13. Tooling cheat sheet

| Command | Purpose |
|---------|---------|
| `topcoat dev` | Build, bundle, serve, watch, HMR (no custom HTTPS) |
| `just run` | **Preferred serve**: custom TLS 1.3 HTTPS + asset bundle |
| `topcoat fmt` | Format `view!` and other macro bodies (`just fmt`) |
| `topcoat asset bundle` | Write `target/assets` (`just bundle`) |
| `topcoat ui …` | **Out of scope** for VCP Concept UI |

Validation: `just validate` = rustfmt check + `topcoat fmt` no-op +
clippy `-D warnings` + asset bundle + tests (`dev-validation-cycle.mdc` /
`quality-assurance`). `just validate` / `just run` / `just bundle` call
`ensure-topcoat` (auto-installs pinned `topcoat-cli` when missing).

**Do not** switch the binary to `topcoat::start` — VCP keeps
`src/tls/serve.rs` for HTTPS.

---

## 14. Anti-patterns (do not import from bastion)

| Avoid | Prefer |
|-------|--------|
| Askama templates | `view!` |
| Axum extractors as the auth model | `cx` functions + memoize |
| HTMX+Alpine as the default stack | Topcoat runtime / shards / PRG |
| First-party JS for fetch/cURL tabs / countdown | Signals + `@` / `:` (see §10) |
| `@click="navigator…; this.…"` (bind-time stmts) | `@click="(e) => { … }"` or `$()` |
| Capsicum `include_bytes!` static registry | `asset!` pipeline |
| Bastion WebSocket dashboards | HTTP CRUD only |
| Trusting procedure/shard args | Re-check session + Casbin + tenant |
| Hardcoded download host constants | `server.public_origins` / `primary_public_origin()` |
| Assuming Topcoat does TLS | Edge TLS 1.3 / PQ (`tls-post-quantum.mdc`) |

---

## 15. Upstream doc index (refresh when needed)

| Source | Use for |
|--------|---------|
| [Announcing Topcoat](https://tokio.rs/blog/2026-07-22-announcing-topcoat) | Motivation, locality, reactivity vs WASM, Axum split, roadmap |
| [Toasty 0.6 announcement](https://tokio.rs/blog/2026-05-15-announcing-toasty-0-6-0) | Deferred / select / `Vec` scalars / collection ops |
| `crates/topcoat/docs/` on GitHub | Getting started, router, context, cookies, sessions, runtime, assets, Tailwind, UI, htmx, alpine-ajax |
| `crates/topcoat-router/docs/module_router.md` | Module router conventions |
| `crates/topcoat-*/macro/docs/` | Macro-specific guides |
| [Toasty guide](https://tokio-rs.github.io/toasty/nightly/guide/) | ORM details beyond the blog |

When behavior is unclear, **fetch the current upstream guide** rather
than guessing from memory of older releases.

---

## 16. Related VCP artifacts

| Artifact | Role |
|----------|------|
| `references/RUNTIME.md` | Signals / `@click` pitfalls / test contracts |
| `web-stack` skill | VCP conventions (incl. Toasty + Postgres) |
| `casbin-permissions.mdc` | AuthZ gates |
| `portal-security.mdc` | Tenancy, CSRF, secrets |
| `tls-post-quantum.mdc` | HTTPS edge / PQ |
| `timezone-localization.mdc` | `vcp_tz` |
| `vcp-test-pyramid.mdc` | Behavioral tests |
| `quality-assurance` skill | fmt / clippy / tests |
| `tests/.../common/topcoat_click.rs` | SSR `@click` function-expression contract |
