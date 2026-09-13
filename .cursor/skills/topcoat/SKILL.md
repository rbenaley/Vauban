---
name: topcoat
description: >-
  Durable knowledge of the Topcoat framework for VCP. Use when scaffolding,
  implementing pages/components/shards/procedures, signals, @click/:bind,
  sessions, cookies, routing, assets, Tailwind/UI, planning a 0.6.2→0.8.0
  upgrade, or when unsure how Topcoat works. Read before inventing
  Axum/Askama/HTMX or first-party UI JS. Current-pin playbook:
  references/UPGRADE-0.6.md. Next bump: references/UPGRADE-0.8.md.
---

# Topcoat knowledge base (VCP)

Canonical upstream: [tokio-rs/topcoat](https://github.com/tokio-rs/topcoat).
Agent map of the repo: upstream `AGENTS.md`. User guides live under each
crate’s `docs/` (embedded into rustdoc).

Announcement / orientation (read when refreshing mental model):

- [Announcing Topcoat](https://tokio.rs/blog/2026-07-22-announcing-topcoat)
  (2026-07-22, Carl Lerche & Julien Scholz)
- [Release v0.5.0](https://github.com/tokio-rs/topcoat/releases/tag/v0.5.0)
  (2026-07-27) — WS / SSE / Datastar / mail / WASM / UDS; breaking API moves
- [Release v0.6.0](https://github.com/tokio-rs/topcoat/releases/tag/v0.6.0)
  (2026-08-17) — concurrent components, `href!`, scoped `Cx::with`,
  router `OriginPolicy`, 2 MiB body cap, `path_param!`, `not_found!`
- [v0.6.1](https://github.com/tokio-rs/topcoat/releases/tag/v0.6.1) /
  [v0.6.2](https://github.com/tokio-rs/topcoat/releases/tag/v0.6.2)
  (2026-08-18) — discover rewrite, `await` in `$()` blocks, `TowerService`
- [v0.7.0](https://github.com/tokio-rs/topcoat/releases/tag/v0.7.0)
  (2026-09-05) — streaming SSR, lazy `View`, `live!` / `error_boundary`
- [v0.8.0](https://github.com/tokio-rs/topcoat/releases/tag/v0.8.0)
  (2026-09-09) — `signal(cx, init)`, tracked server reads, morph,
  `.runtime()`
- Sibling ORM: [Toasty 0.6.0 — what is new?](https://tokio.rs/blog/2026-05-15-announcing-toasty-0-6-0)
  (field select / deferred / `Vec` scalars; VCP pins **0.10** — see
  `Cargo.toml` / `toasty` skill)

This skill captures a study of Topcoat for the **Vauban Customer Portal**.
VCP product constraints that override framework capabilities are marked
**VCP**. Broader conventions live in the `web-stack` skill and the
`.cursor/rules/*.mdc` set.

**Last studied:** 2026-09-13 against upstream tag **v0.8.0** (commit
`149f0de`; edition **2024**, MSRV **1.98**, workspace
`unsafe_code = deny`). Temporary study clone:
`/tmp/topcoat-0.8-study`. Durable clone: `/Users/mnemonic/Code/topcoat`.
Source map:
[tokio-rs/topcoat@v0.8.0](https://github.com/tokio-rs/topcoat/tree/v0.8.0).

**VCP pin:** facade + `topcoat-cli` **0.8.0** (`Cargo.toml` /
`Justfile`; VCP `rust-version` **1.98**). Write **0.8** forms:
`let name = signal(cx, || …)` above `view!`, `-> Result<impl View>` +
`Ok(view!)`, `slot: Slot<'_>` + `error_boundary`, `.runtime()` before
`runtime::script`. Use `href!`, `path_param!`, `OriginPolicy`,
`BodyLimit`, `Cx::with`, and `not_found!`. Keep 0.5 / 0.6 notes
historical.

- Historical 0.4→0.5 (done): [`references/UPGRADE-0.5.md`](references/UPGRADE-0.5.md)
- 0.5→**0.6.2** (done): [`references/UPGRADE-0.6.md`](references/UPGRADE-0.6.md)
- 0.6.2→**0.8.0** (done): [`references/UPGRADE-0.8.md`](references/UPGRADE-0.8.md)

Re-check crates.io / GitHub if months have passed — early-stage.

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
- Ecosystem story (upstream): **Toasty** (ORM) then **Topcoat** (web).
  **0.5.0** ships first-party **mail** (`topcoat-mail`); roadmap still
  lists tighter Toasty forms/validations, streaming SSR, auth helpers —
  wire today’s APIs; do not wait for future sugar.
- Serving is separable: feature `serve` (default on) owns hyper/tokio
  accept; apps can call `Router::handle(request)` without a listener
  (WASM / serverless). On Unix, `serve` accepts `UnixListener` via the
  `Listener` trait (TCP or UDS behind a reverse proxy).

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
| `topcoat` | Facade / re-exports; `serve` / `start` / `serve_until` behind `serve` |
| `topcoat-core` | `Error`/`Result`, `Cx`, app/request context, `#[memoize]`, `BaseUrl` |
| `topcoat-view` | `view!`, `attributes!`, `class!`, `#[component]` (`boxed` for recursion) |
| `topcoat-router` | `Router` / `Router::handle`, pages/layouts/layers, `module_router!`, `content` / `error` / `tower` |
| `topcoat-runtime` | Signals, `$(...)` / `expr!`, `#[procedure]`, `#[shard]`, browser script asset |
| `topcoat-asset` | `asset!` → `Asset` **handle** + `AssetId`; `AssetBundle`; `hosted_at` + manifest |
| `topcoat-cookie` | Cookie jar, `cookie!`, signed/private jars, `CookieStore<T>` |
| `topcoat-session` | BYO-storage sessions; `SessionConfig` / `SessionConfigBuilder`. **0.5:** `.sessions()` still installs origin checks. **0.6:** origin moves to the router (`OriginPolicy`); session crate no longer owns CSRF |
| `topcoat-mail` | `mail!` + `send`; SMTP / file / memory transports (**0.5+**) |
| `topcoat-datastar` | Datastar SSE patches (`datastar` feature ⇒ `sse`) (**0.5+**) |
| `topcoat-font` / `topcoat-icon` | Web fonts, Iconify |
| `topcoat-tailwind` | Standalone Tailwind CLI via build script |
| `topcoat-ui` | Registry for `topcoat ui` (copy components into the app) |
| `topcoat-htmx` / `topcoat-alpine-ajax` | Optional header helpers |
| `topcoat-cli` | `topcoat` binary: `dev`, `fmt`, `ui`, `asset bundle` (scans cdylib too) |

Macro crates usually come as **trio**: runtime types + `grammar/` + `macro/`.

---

## 3. Features (facade)

**Default** (0.5): `asset`, `compression`, `cookie`, `font`, `icon`,
`router`, `runtime`, `serve`, `session`, `view`, `discover`.

**`full`** (0.5 and 0.6) also pulls: `alpine-ajax`, `datastar`,
`font-fontsource`, `htmx`, `icon-iconify`, `mail`, `mail-smtp`,
`multipart`, `sse`, `tailwind`, `tower`, `ui`, `websocket`. **0.6**
adds `sitemap` to `full`.

Notable optionals:

| Feature | Notes |
|---------|--------|
| `serve` | Default on; required for `topcoat::serve` / `start` and for `websocket` |
| `sse` | Server-sent events (`content::sse`) |
| `websocket` | Needs `serve`; `content::websocket` |
| `datastar` | Implies `sse` |
| `mail` / `mail-smtp` | `topcoat-mail` |
| `tower` | `TowerLayer` + `TowerRoute`; **0.6.2** also `TowerService` (Topcoat as Axum service) |
| `sitemap` | **0.6+** `content::sitemap::{Sitemap, SitemapUrl}` |
| `tailwind` / `ui` / `htmx` / `alpine-ajax` | As before |

**VCP:** leave `websocket` / `datastar` / `sse` off unless a product
slice needs them. Keep `tailwind` + `font-fontsource`. Do not vendor `ui`.

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
- `#[component(boxed)]` (**0.5+**): break async future cycles for
  recursive components (comment threads, trees).
- `attributes!` / `class!` / `props!`: attribute fragments and class lists.
- Boolean attrs render as `disabled=""` when true (**0.5+**; was
  `disabled="true"`). **Only the Rust `bool` `false` omits the
  attribute.** Update HTML snapshot asserts accordingly.
- Components may be async and talk to the DB directly — no mandatory
  separate JSON API for HTML.
- **0.6 concurrent rendering (automatic):** sibling / loop / nested
  `#[component]` calls in one `view!` start in the same tick. Output
  stays in source order; **await interleaves**. A `for` of N
  components fires N I/O calls at once — do not loop unbounded
  user-controlled rows into per-row DB components. Rendered `View`s
  live in an arena (not `Send` to another thread). 0.5 is still
  sequential.

### Boolean attributes and `<select>` (mandatory)

HTML boolean attributes (`selected`, `checked`, `disabled`, `required`,
…) are **presence-based**. Topcoat emits the attr whenever the value is
not the bool `false`.

| OK | Forbidden |
|----|-----------|
| `selected=(cond)` / `selected=(true)` | `selected=(if cond { "selected" } else { "" })` |
| `disabled=(busy)` | `disabled=(if busy { "disabled" } else { "" })` |
| Branch: `if cond { <option selected=(true)> } else { <option> }` | Putting `selected=""` on **every** `<option>` in a `for` loop |

**Why:** `else { "" }` still renders `selected=""` on non-matching
options. For a single-select, the browser keeps the **last** marked
option — VCP hit this on admin release edit (`Channel` flipped to EOL,
`Target organization` to the last org alphabetically). Saving then
rewrote the row to the wrong client/channel.

**VCP pins:** `scripts/check_topcoat_boolean_attrs.sh` (run via
`topcoat_boolean_attrs_invariants_test`). Prefer precomputed `bool`s
outside `view!` when several options share one stored value:

```rust
let channel_stable = rel.channel == "Stable";
// ...
<option value="Stable" selected=(channel_stable)>"Stable"</option>
```

Upstream guides: `topcoat-view/macro/docs/view.md`, `component.md`, etc.

---

## 6. Routing

- Manual: register `#[page]`, `#[layout]`, `#[route]` on `Router::builder()`.
- Discover: `.discover()` + inventory (feature `discover`).
- Module router: derive URL tree from `src/app.rs` + `src/app/**`
  (kebab segments; `_prefix` layouts without a URL segment;
  `segment!` overrides).
- Path/query: **0.5** `#[path_param]` + `#[query_params]`. **0.6**
  removes the attribute — `path_param!(org);` / `path_param!(id: u64)`
  (see `UPGRADE-0.6.md`). Catch-all: `path_param!(*doc_path)`.
- Layouts nest by path prefix (least-specific outermost).
- Methods (**0.5+**): `#[route([GET, POST] "/…")]`, `#[route(* "/…")]`,
  `#[page(POST "/…")]`. Specific-method routes beat `*` at the same path.
- Dispatch entry: `Router::handle(Request) -> Response` (used by serve,
  tests, and listener-less runtimes).
- `RouterBuilder::base_url("https://…")` (**0.5+**): absolute public URL
  for mail / feeds / sitemaps (`base_url(cx)`).
- Errors / bodies: see §6.1 (module moves in **0.5**).
- Tower: `router::tower::{TowerLayer, TowerRoute}` behind `tower` —
  **transport** concerns, not app auth. `TowerRoute` mounts an Axum /
  hyper service under a catch-all path. **0.6.2** inverse:
  `TowerService::new(topcoat_router)` as an Axum fallback. VCP keeps
  `src/tls/serve.rs` — do not switch hosts on a pin bump.
- **0.6 URL builders:** `href!(page_fn, Param(v))` in `view!`;
  `.resolve(cx)` for `see_other` / mail. Required for in-app portal URLs.

**VCP:** prefer module-based routing + discover for the portal tree.

### 6.1 Module layout (0.5 breaking)

Imports moved out of the router root. Prefer these paths on **0.5+**:

| Kind | Path |
|------|------|
| Status helpers / types | `topcoat::router::error::{not_found, see_other, forbidden, SeeOther, RouterErrorExt, …}` |
| Bodies / extractors | `topcoat::router::content::{Form, Html, Json, Css, RawForm, …}` |
| Multipart | `topcoat::router::content::multipart::Multipart` |
| SSE | `topcoat::router::content::sse::{Sse, Event, KeepAlive, last_event_id}` |
| WebSocket | `topcoat::router::content::websocket::{WebSocketUpgrade, Message}` |
| Tower | `topcoat::router::tower::{TowerLayer, TowerRoute}` (+ `TowerService` on **0.6.2**) |
| Unchanged at root (0.5) | `StatusCode`, `Method`, `Body`, `Bytes`, `FromRequest`, `IntoResponse`, … |
| **0.6 move** | `Bytes` / `FromRequest` / accessors → `router::request::*`; `IntoResponse` / `Response` → `router::response::*` |

Guides: `crates/topcoat-router/docs/error.md`, `content.md`, `tower.md`.

### 6.3 Router 0.6 (apply only after pin bump)

Full checklist: `references/UPGRADE-0.6.md`. Hits that **will not compile**
or will **change production behavior** on VCP:

| Surface | 0.5 today | 0.6.2 |
|---------|-----------|--------|
| Layer ctx | `&mut CxBuilder` (`security_headers`) | `&Cx`; child via `cx.with(...)` |
| CSRF | `SessionConfig::trust_origin` | `RouterBuilder::origin_policy(OriginPolicy::…)` |
| Path params | `#[path_param] struct Org(str)` | `path_param!(pub org);` |
| Body extractors | Uncapped (practically) | **2 MiB** default → 413 on pkg/image multipart unless `BodyLimit` |
| Unknown URL | Layouts still wrap 404 | Bare 404 unless `not_found!("/")` |
| Memoize `Option` | Auto `Option<&T>` | Need `#[memoize(as_ref)]` |
| Assets | `target/assets` search | Bundle **next to the binary** |

Write these 0.6 forms (VCP is on 0.6.2). 0.8 drops the `signal`
statement and restores layout `Slot<'_>` — see `UPGRADE-0.8.md`; do
not use those forms until the pin moves.

**Concurrent `for` in `view!` (0.6):** each `#[component]` iteration
starts together. Keep SQL paging in the page/shard (`limit`/`offset`)
and pass already-loaded rows into the loop. Do **not** turn list rows
into N DB-hitting components (`src/list_page.rs` stays `?page=N`).
Hot spots today are chips/pager/note lines and search-shard row markup
— they render preloaded structs only. Org dashboard tiles are sibling
`#[component]`s over `#[memoize]` loaders (`src/app/org/dashboard_tiles.rs`).
Transactional mail uses `mail!` + `view!` bodies (`src/mail_views.rs`);
`email/*.html` are visual fixtures only.

### 6.2 Layouts: `Slot` → rendered `Result` (0.5 breaking)

| | 0.4 | 0.5+ |
|---|-----|------|
| Param | `slot: Slot<'_>` | `slot: Result` (already-rendered child) |
| Embed | `(slot.await?)` | `(slot?)` |
| Type | `topcoat::router::Slot` | **removed** |

Layouts can `downcast_ref` child errors (e.g. branded 404) before wrapping
chrome — see upstream error guide. Trade-off: the page finishes rendering
before any layout body runs (matters for a future streaming SSR design).

**VCP (0.8):** every `#[layout]` uses `slot: Slot<'_>` + `error_boundary`.
Do not reintroduce `Slot` on the current pin (pinned by
`check_portal_shell` + `portal_shell_invariants`). **0.8 reverses
this:** `slot: Slot<'_>` + `error_boundary` around `(slot)` — only
after the pin bump (`UPGRADE-0.8.md`).

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
- Canonical trailing-slash (and similar wide URL fixes): pathless `Layer` (`path() -> None`) + `redirect_permanent` + pure path helper — see `src/http_canonical.rs` and `references/RUNTIME.md`. `#[layer]` in `app` is scoped to `/` and does **not** run on unmatched `/login/`.
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
  flushed at end of request. **0.6:** writing a cookie after the
  response is sent **panics** (was a silent no-op). Keep writes in the
  handler.
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

**Naming:** import `session::SessionConfig` directly (0.5 renamed the
old `session::Config` type).

Resolve user: `token_hash(cx)` → lookup in your DB → `None` if missing
or expired. Guard with `ok_or_redirect("/login")` / unauthorized helpers.

### CSRF / OriginLayer

**0.5 (current pin):** `.sessions()` registers **`OriginLayer`**:

- For methods other than GET/HEAD/OPTIONS, requires
  `Sec-Fetch-Site: same-origin|none`, or matching `Origin` host for older
  browsers.
- Requests with neither header pass (non-browser clients).
- Trust extra origins via `SessionConfig::builder().trust_origin(...)`.

**0.6 (on bump):** origin verification is the **router’s** outermost
step (`OriginPolicy` / `RouterBuilder::origin_policy`), on every
`Router`, sessions or not. `SessionConfig::trust_origin` and
`topcoat_session::OriginLayer` are **gone**. WebSocket upgrades are
treated as state-changing (VCP still leaves `websocket` off). See
`UPGRADE-0.6.md`.

**VCP:** keep origin checks always on (`trust_origin` / 0.6
`trust_origins` from `server.public_origins`); mutations on POST
(etc.); never state-changing GET; never `dangerous_disable`. Read-only
list filters may use GET forms (docs / issues search). Aligns with
`portal-security.mdc`.

Custom `TokenStore` can put the token in `Authorization: Bearer` for M2M
instead of a cookie.

---

## 10. Runtime (reactivity) — experimental

Upstream warns: **highly experimental**, limited expression vocabulary,
breaking changes expected. **VCP does not** adopt HTMX / Alpine as the
default. Deep playbook: [`references/RUNTIME.md`](references/RUNTIME.md).
On **0.6.2** keep `signal name = value;` inside `view!`. On **0.8**
that statement is gone (`signal(cx, init)` + `.runtime()`) —
`UPGRADE-0.8.md`.

### Layers

| Layer | Where | VCP use |
|-------|-------|---------|
| **Signals + `$(...)` / `@` / `:`** | Browser | Tabs, countdown, show/hide, copy affordances |
| **`#[shard]`** | Server HTML swap | Live search / filtered lists needing DB |
| **GET filter forms** | Full navigation | Docs/issues search fallback (shareable `?q=` URLs); **not** mutations |
| **`#[procedure]`** | Server RPC | Imperative actions (args untrusted) |
| **POST + PRG** | Full navigation | Auth, mint/revoke tokens, admin mutations |

**VCP split:** mint entitlements / tokens **server-side** (POST/PRG + DB).
Use Topcoat signals only for **ephemeral UI** after SSR. Do **not** add
first-party `assets/vcp_*.js` for toggles the runtime can express.

**GET filter forms (idiomatic):** list search on docs / org issues /
admin issues uses `method="GET"` as progressive-enhancement fallback
beside the live shard. That is a filter, not a mutation — OriginLayer
does not apply, and converting these to POST would break shareable
query URLs. Compose / report / reply forms stay `method="POST"`.

**VCP list pagination:** list paging is **SSR GET** (`?page=`, shareable
`<a href>`). Do **not** invent a client/JS pager. Live-search `#[shard]`s
receive `page` as an arg and slice after filter/sort; when the search
signal updates, reset to page 1. Placement and helpers: `web-stack`
skill § List pagination (`LIST_PAGE_SIZE`, `filter_row` / `vb_pager`).

### Non-negotiable: `@click` bind contract

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
- **Ticks:** `.vb-eph-tick` CSS + `@animationiteration`; countdown math must
  use `data-expires-at` + `Date.now()` (raw handler) — never `remaining -= 1`.
- **Tabs without navigation:** one `signal use_curl = false` +
  `@click=$(|_e| use_curl.set(true/false))` + reactive cmd text /
  `:data-copy` — never `?tool=` round-trips.
- **Config in handlers:** put `Arc<Config>` in `app_context`; read via
  `auth::config(cx)` (absolute URLs → `primary_public_origin()`).
- **Signal shorthands (0.5+):** `toggle()` on `bool`, `increment` /
  `decrement` on `f64`, `push_str` on `String` (prefer over
  `set(get() ± 1)`).
- **`topcoat fmt`:** formats `signal` decls and `mail!` bodies;
  `--stdin` fails non-zero on format errors. `just topcoat-fmt` runs
  over all `src/**/*.rs`.

### Mechanics checklist

- `topcoat::runtime::script()` in root layout + `AssetConfig` on router
  (`just bundle` / `just run`).
- `$(...)`: dual Rust + JS; text nodes skip first DOM patch (SSR text
  stays until the signal changes).
- Scan order is document order: an early throwing `@click` kills later
  binds on the same page.
- Shard / procedure args: **re-auth + re-authorize every time.**


## 11. Assets, Tailwind, UI

- `const X: Asset = asset!("./file.png");` → content-hashed URL; serve via
  bundle from `topcoat` CLI / `AssetBundle::load()`.
- **0.5 handle model:** `asset!` returns an `Asset` handle (keeps the
  embedded declaration alive). Bundle lookup uses `AssetId` via
  `handle.id()`. An unused handle can be optimized out — **use every
  declared asset** or the bundler will not see it. Bundle entries expose
  a relative `name()` under `bundle.dir()` (not an absolute path).
- **Hosted assets (0.5):** `AssetConfig::hosted_at(base_url, manifest)` —
  arg order is **URL first**, then manifest/bundle. For WASM / CDN:
  embed `manifest.toml` with `include_str!` when there is no on-disk
  bundle directory.
- Tailwind: feature `tailwind`, `topcoat::tailwind::stylesheet!()` —
  standalone CLI, no Node required for that path. VCP input CSS is
  `styles.css` (`@import "tailwindcss"`, `@source`, Concept `@theme`).
- Fonts: feature `font-fontsource` + `fontsource_font!` (see `src/fonts.rs`).
- Icons: Iconify sets via `iconify::include!("…")` when needed (optional).
- `topcoat ui`: shadcn-inspired **copy-into-your-tree** Tailwind components
  (`topcoat ui …`). **Optional / out of scope for VCP** — keep Concept
  `vb-*` under `src/app/_components/`; do not vendor Topcoat UI defaults.

**VCP exception — OS / browser icon probes:** hashed `asset!` URLs cannot
satisfy fixed probes (`/favicon.ico`, `/apple-touch-icon.png`,
`/apple-touch-icon-precomposed.png`). Those routes may use
`include_bytes!` + `Response::builder` with a long `Cache-Control`.
HTML `<link rel="icon">` / apple-touch in the root layout still use
`asset!`. Do **not** generalize this pattern to other static files;
do **not** redirect probes to hashed URLs.

**VCP required idioms**

| Idiom | Where |
|-------|--------|
| `#[layout]` + `Slot<'_>` + `error_boundary` | Root (`app.rs`), login splash, org chrome |
| `#[component]` | `app/_components/*` (rail, topbar, modal, chips, badges) |
| `stylesheet!()` + `runtime::script()` + `dev::script()` | Root layout `<head>` |
| `AssetBundle::load()` → `AssetConfig` | Fail closed if missing/stale; boot checks favicons, Tailwind, runtime script resolve (0.5 Tailwind IDs embed `OUT_DIR` — always `just bundle` / `just run`, never bare `cargo run` after rebuild) |
| `just bundle` / `topcoat asset bundle` | After build so CSS/runtime assets resolve |

**VCP:** brand toward Concept / `vauban.sh`, not bastion dark admin chrome
or Topcoat UI purple defaults. Responsive: `responsive-ui.mdc`.

---

## 12. Optional integrations

| Feature | Use when |
|---------|----------|
| `htmx` / `alpine-ajax` | Partial HTML swaps via those libs’ headers |
| `tower` | Bridge tower services/layers (`TowerRoute` for legacy subtrees) |
| `sse` | Long-lived `text/event-stream` (`KeepAlive`, `Last-Event-ID`) |
| `datastar` | Backend-driven patches (`Signals`, `PatchElements` / `PatchSignals`) |
| `mail` / `mail-smtp` | Transactional email via `mail!` + `send` + `MailConfig` |
| `websocket` | **VCP: do not enable** unless product explicitly needs it |

Mail sketch (0.5+, not used in VCP yet):

```rust
let mail = mail! {
    from: ("VCP", "noreply@example.com"),
    to: "ada@example.com",
    subject: "Welcome",
    html: { <p>"Ready."</p> },
}?;
send(cx, mail).await?;
```

Register a transport on the router (`SmtpTransport` / `FileTransport` /
`MemoryTransport` for tests). Pair with `.base_url(...)` for absolute
links in message bodies.

### ORM (VCP locked): Toasty + PostgreSQL

- **ORM skill (read this):** project skill **`toasty`** — query API
  (`filter` / `limit`+`offset` / `count` / `order_by` / `ilike` /
  `in_list` / `.or`), migrations, and the ban on full-table
  `Model::all()` + Rust filter/sort/page. Pin **0.10.0** + Postgres.
- **ORM:** [Toasty](https://github.com/tokio-rs/toasty). Topcoat example:
  `examples/toasty-todo` (SQLite there; **VCP uses PostgreSQL**).
- **Guide:** [Toasty guide](https://tokio-rs.github.io/toasty/nightly/guide/).
- Orientation: [Toasty 0.6 announcement](https://tokio.rs/blog/2026-05-15-announcing-toasty-0-6-0)
  (deferred / select / `Vec` scalars; confirm against 0.10).
- Wire via `app_context` + `db(cx)` today (`web-stack`). Escape hatch:
  narrow `sqlx` only after the `toasty` skill’s SQL APIs are exhausted —
  not a second data model.
- Debt tracker:
  `.cursor/audits/vcp_architecture_toasty_query_debt_2026-08-02.md`.

Scaffolded models: `User`, `AuthSession`, `Organization`, `Membership`,
`DocArticle` / `Release` / `Issue`, … Client routes `/{org}/…`; staff
under `/admin/…` (`web-stack`).

---

## 13. Tooling cheat sheet

| Command | Purpose |
|---------|---------|
| `topcoat dev` | Build, bundle, serve, watch, HMR (no custom HTTPS) |
| `just run` | **Preferred serve**: custom TLS 1.3 HTTPS + asset bundle |
| `topcoat fmt` | Format `view!` and other macro bodies (`just fmt`) |
| `topcoat asset bundle` | **0.5:** `target/assets`. **0.6:** next to the scanned binary (`target/debug/assets`). `just bundle` must stay in sync — see `UPGRADE-0.6.md` |
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
| Capsicum `include_bytes!` static registry | `asset!` pipeline (well-known icon **probes** only: §11) |
| Bastion WebSocket dashboards | HTTP CRUD only |
| Trusting procedure/shard args | Re-check session + Casbin + tenant |
| Hardcoded download host constants | `server.public_origins` / `primary_public_origin()` |
| Assuming Topcoat does TLS | Edge TLS 1.3 / PQ (`tls-post-quantum.mdc`) |

---

## 15. Upstream doc index (refresh when needed)

Prefer docs at tag **v0.8.0** for current-pin work:

| Source | Use for |
|--------|---------|
| [Announcing Topcoat](https://tokio.rs/blog/2026-07-22-announcing-topcoat) | Motivation, locality, reactivity vs WASM, Axum split, roadmap |
| [v0.5.0 release notes](https://github.com/tokio-rs/topcoat/releases/tag/v0.5.0) | Breaking changes, WS/SSE/Datastar/mail/WASM/UDS |
| [v0.6.0–v0.6.2 notes](https://github.com/tokio-rs/topcoat/releases/tag/v0.6.0) | Concurrent views, `href!`, `Cx::with`, origin/body/404/`path_param!` |
| [v0.7.0](https://github.com/tokio-rs/topcoat/releases/tag/v0.7.0) / [v0.8.0](https://github.com/tokio-rs/topcoat/releases/tag/v0.8.0) | Lazy `View`, `error_boundary`, `signal(cx)`, morph, `.runtime()` |
| Project **`UPGRADE-0.6.md`** | VCP 0.5→0.6.2 checklist (done) |
| Project **`UPGRADE-0.8.md`** | VCP 0.6.2→0.8.0 checklist (done) |
| [Toasty 0.6 announcement](https://tokio.rs/blog/2026-05-15-announcing-toasty-0-6-0) | Deferred / select / `Vec` scalars / collection ops |
| Project **`toasty` skill** | VCP ORM conventions + query anti-patterns |
| `crates/topcoat/docs/` | Getting started, app context, mail, Datastar, UI, … |
| `crates/topcoat-router/docs/{error,content,tower,module_router}.md` + `content/{sse,websocket,multipart}.md` | Router surface after 0.5 split |
| `crates/topcoat-*/macro/docs/` | Macro-specific guides |
| Upstream `AGENTS.md` / `.agents/skills` | Maintainer agent map |
| [Toasty guide](https://tokio-rs.github.io/toasty/nightly/guide/) | ORM details beyond the blog |

When behavior is unclear, **fetch the current upstream guide** rather
than guessing from memory of older releases.

---

## 16. Related VCP artifacts

| Artifact | Role |
|----------|------|
| `references/RUNTIME.md` | Signals / `@click` pitfalls / test contracts |
| `references/UPGRADE-0.5.md` | 0.4 → 0.5 migration checklist (done; historical) |
| `references/UPGRADE-0.6.md` | 0.5 → **0.6.2** playbook (historical) |
| `references/UPGRADE-0.8.md` | 0.6.2 → **0.8.0** playbook (done; current pin) |
| `web-stack` skill | VCP conventions (routing, `db(cx)`, page sizes) |
| `toasty` skill | Toasty 0.10 query / migration playbook |
| `casbin-permissions.mdc` | AuthZ gates |
| `portal-security.mdc` | Tenancy, CSRF, secrets |
| `tls-post-quantum.mdc` | HTTPS edge / PQ |
| `timezone-localization.mdc` | `vcp_tz` |
| `vcp-test-pyramid.mdc` | Behavioral tests |
| `quality-assurance` skill | fmt / clippy / tests |
| `tests/.../common/topcoat_click.rs` | SSR `@click` function-expression contract |
