# Upgrade Topcoat 0.5 → 0.6.2 (VCP playbook)

Upstream:

- [v0.6.0 notes](https://github.com/tokio-rs/topcoat/releases/tag/v0.6.0)
  (2026-08-17)
- [v0.6.1](https://github.com/tokio-rs/topcoat/releases/tag/v0.6.1) —
  rewrite through `discover`; `await` in `ExprBlock` / `ExprIf`
- [v0.6.2](https://github.com/tokio-rs/topcoat/releases/tag/v0.6.2)
  (latest) — `TowerService` (Topcoat as Axum fallback); control-flow
  futures own their pattern bindings

Studied tree: clone `tokio-rs/topcoat` at tag **v0.6.2**
(`92a76709`). Facade docs: `crates/topcoat/CHANGELOG.md`,
`crates/topcoat/docs/`, `AGENTS.md`.

**Status:** VCP still pins **0.5.0** (`Cargo.toml` / `Justfile`
`topcoat_cli_version`). This file is the checklist and the features to
**exploit**. Do **not** call 0.6-only APIs (`href!`, `Cx::with`,
`path_param!`, `OriginPolicy`, `not_found!`, `BodyLimit`) until the
facade + CLI are bumped together.

Bump target: **0.6.2** (not 0.6.0). 0.6.1/0.6.2 are compile/runtime
fixes VCP needs (`module_router!` + `rewrite`, `await` in `$()`,
control-flow bindings).

---

## Pins to bump together

| Location | Change |
|----------|--------|
| `Cargo.toml` facade | `topcoat = "0.6.2"` (same features; add `sitemap` only if a route needs it) |
| `Justfile` | `topcoat_cli_version := "0.6.2"` |
| Host CLI | `cargo install topcoat-cli --version 0.6.2` (or `ensure-topcoat`) |

**CLI first.** 0.6 writes the asset bundle **next to the scanned
binary** (`target/debug/assets`, `target/release/assets`).
`AssetBundle::load()` looks **only** there. An old 0.5 CLI still writes
`target/assets`; the 0.6 runtime never reads it — first HTML render
fails to resolve assets. The 0.6 CLI also warns when it does not match
the crate pin.

`just bundle` / `ensure-asset-bundle` / `pkg/build-pkg.sh` /
`load_asset_bundle` in `src/app.rs` today assume `target/assets` +
`AssetBundle::load_dir(package_root/assets)`. On bump: either follow
exe-adjacent layout or keep `load_dir` + `--out` and document it.
Packaged `/usr/local/share/vcp/assets` via `load_dir` still works.

---

## Exploit on bump (do not invent 0.5 workarounds)

| 0.6 addition | VCP use |
|--------------|---------|
| Concurrent `#[component]` I/O in `view!` | Free latency: sibling rail / tiles / cards that each query DB run together. Page time ≈ slowest query, not the sum. **Caveat:** a `for` over N components fires N queries at once — do not loop unbounded user data into per-row DB components. |
| `href!` / `href(...).resolve(cx)` | Typed URLs for `<a>`, `see_other`, mail bodies. Stop hand-writing `/{org}/issues/{key}`. Params match **by name** (wrong type panics at resolve). `.query(...)` / `.fragment(...)` / `.absolute()`. |
| `Cx::with` / `Cx::with_many` | Replace `CxBuilder` / `&mut Cx` inserts. `security_headers` layer becomes `&Cx` + `next.run(&cx, body)`. `Cx` is `Clone` + `Send + Sync` (`Arc`) — prefer clone over the old `detach`. |
| `OriginPolicy` on every `Router` | CSRF moves out of `SessionConfig::trust_origin`. Register `.origin_policy(OriginPolicy::new().trust_origins(cfg.server.public_origins))`. Keep mutations on POST. Do **not** call `dangerous_disable()`. |
| `BodyLimit` (default **2 MiB**) | **Must raise** on release pkg upload, org images, issue screenshots (`Multipart`). `BodyLimit::max(n).at("/admin/releases")` (and images / issues paths) or previously-working uploads return **413**. |
| `not_found!("/")` (+ prefix variants) | 0.6 no longer runs layouts/layers on unmatched URLs. Without a catch-all, branded chrome 404s disappear. Register `not_found!("/")` (and `/admin` if needed) so root/org layouts can `downcast_ref::<NotFoundError>()`. |
| `path_param!(name: T)` | Replaces `#[path_param]`. Generates PascalCase type. `path_param!(pub org);` for `Org(str)`. Catch-all `path_param!(*doc_path)` — use for multi-segment routes instead of `raw_path_params` (ephemeral `{eph_token}/{eph_pkg}`). |
| `#[memoize]` Hash-only + scope-aware | Args need `Hash` only (no `Clone + Eq`). `Cx::with` cannot leak a memoized value across scopes. |
| `#[memoize(as_ref)]` | **Required** on VCP helpers that return `Option<T>` and are used as `Option<&T>`: `session_user`, `org_context`, `resolve_org_id_memo`. Without it, call sites get `&Option<T>`. |
| Promoted / `StaticClass` | Optional. Literal `class!` is cheaper. Vendored `topcoat-ui` only — VCP does not vendor UI. |
| `rewrite(path, body)` | Internal re-dispatch (not a redirect). Cap 8 hops. Useful later for reserved-org aliases; not required on day one. |
| `Sitemap` (`sitemap` feature) | Additive. Pair with existing `.base_url(...)`. Relative entries **panic** without a base URL. |
| `TowerService` (0.6.2) | Embed Topcoat **inside** Axum (`fallback_service`). Inverse of `TowerRoute`. VCP owns HTTPS in `src/tls/serve.rs` — do not switch unless a hybrid host is planned. |
| `too_many_requests` / `service_unavailable` | Retry-After helpers in `router::error`. Use for login limiter / mail circuit instead of raw 429/503. |

**Already in 0.5 (keep):** `slot: Result`, `router::error` / `content`,
`SessionConfig`, `mail!`, module router, signal shorthands, boolean
attrs. Do not re-apply `UPGRADE-0.5.md`.

**Do not enable on bump:** `websocket`, `datastar`, `sse` (VCP product
is HTTPS CRUD). Do **not** vendor the 17 new `topcoat-ui` components
(keep Concept `vb-*`).

---

## Mechanical code migrations

### 1. CLI + assets (do this first or HTML is blank)

```text
0.5: topcoat asset bundle  ->  target/assets/
0.6: topcoat asset bundle  ->  <dir-of-scanned-bin>/assets/
     AssetBundle::load()   ->  current_exe().parent()/assets
```

VCP `src/app.rs` `load_asset_bundle`: packaged `load_dir` stays.
Local fallback `AssetBundle::load()` starts working **only** if the
bundle sits next to `target/{debug,release}/vcp`. Update `Justfile`
(`ensure-asset-bundle`, `just bundle`, `just test` profile) and
`pkg/build-pkg.sh` if they still copy/`--out` to `target/assets`.
`topcoat asset clean` now wipes every bundle under `target/`.

### 2. `CxBuilder` / layers (`src/app.rs`)

```rust
// 0.5
use topcoat::context::{Cx, CxBuilder};
#[layer]
async fn security_headers(cx: &mut CxBuilder, body: Body, next: Next<'_>) -> Result<Response> {
    let response = next.run(cx, body).await...;
}

// 0.6
use topcoat::context::Cx;
#[layer]
async fn security_headers(cx: &Cx, body: Body, next: Next<'_>) -> Result<Response> {
    // If you must register a value for descendants:
    // let cx = cx.with(RequestTimer::start());
    let response = next.run(cx, body).await...;
}
```

Gone: `Cx::insert`, `Cx::get_mut`, `Cx::detach`, `CxBuilder`.
`ContextMap` → `AppContext` (tests / custom `Cx::new` only).
`Next::run` is `#[must_use]`.

Root `#[layer]` (no path) still wraps **every** request including 404/405.
Path-scoped layers do **not** run on unmatched URLs (see §5).

### 3. Origin / CSRF (`src/app.rs`, lints)

```rust
// 0.5
let mut sessions = SessionConfig::builder();
for origin in &cfg.server.public_origins {
    sessions = sessions.trust_origin(origin.clone());
}

// 0.6
use topcoat::router::OriginPolicy;
let router = /* module_router */ ()
    .origin_policy(
        OriginPolicy::new().trust_origins(cfg.server.public_origins.iter().cloned()),
    )
    .sessions(SessionConfig::default()) // no origin methods
    ...
```

Update `scripts/check_auth_tenant.sh` + `auth_tenant_invariants_test`:
pin `OriginPolicy` / `trust_origins`, still forbid
`dangerous_disable`. WebSocket handshakes are now treated as
state-changing (VCP does not enable `websocket`).

### 4. `#[path_param]` → `path_param!`

Mechanical. Read sites `path_param::<T>(cx)` stay.

| File | 0.5 | 0.6 |
|------|-----|-----|
| `src/app/org.rs` | `#[path_param] pub struct Org(str);` | `path_param!(pub org);` |
| `src/app/org/docs/doc.rs` | `struct Doc(str)` | `path_param!(doc);` |
| `src/app/admin/docs/doc.rs` | same | `path_param!(doc);` |
| `src/app/org/builds/release_ver.rs` | `ReleaseVer(str)` | `path_param!(pub(super) release_ver);` |
| `src/app/org/images.rs` | `ImageFile(str)` | `path_param!(image_file);` |
| `src/app/org/issues/issue_key.rs` | `IssueKey(str)` | `path_param!(issue_key);` |
| `src/app/admin/issues/issue_key.rs` | same | `path_param!(issue_key);` |
| `src/app/admin/companies/company_id.rs` | `CompanyId(str)` | `path_param!(company_id);` |
| `src/app/admin/releases/release_id.rs` | `ReleaseId(str)` | `path_param!(release_id);` |

`str` params become an untyped `path_param!(name);` (still `&str` on
read). Typed: `path_param!(post_id: u64, error = bad_request);`.

**Exploit:** `ephemeral_download_get` today walks `raw_path_params`
because 0.5 allows one `#[path_param]` per module. On 0.6 declare
`path_param!(eph_token); path_param!(eph_pkg);` (or a catch-all) and
drop the manual scan.

### 5. Unmatched URLs + `not_found!`

0.6 answers bare 404/405 **without** layouts. VCP root/org/admin chrome
will not wrap unknown paths unless:

```rust
use topcoat::router::not_found;
not_found!("/");
// optional: not_found!("/admin");
```

Then in the root layout, brand via `downcast_ref::<NotFoundError>()`
(same pattern as `UPGRADE-0.5.md` optional follow-up — now **required**
for chrome 404s).

`RouterBuilder::build()` **panics** if a path-scoped layer matches no
route (`layer with path /admin did not match any route`). Root `"/"`
layers are exempt. Fix dead layers; do not disable the check.

### 6. Body size (413)

Default 2 MiB on `Bytes`, `Json`, `Form`, `RawForm`, `Html`, `Css`,
`Multipart`. VCP multipart surfaces that exceed 2 MiB in production:

- `admin_releases_create` / `admin_releases_validate_pkg` (pkg binaries)
- `org_image_upload`
- issue report / reply screenshot fields

Register `BodyLimit::max(...).at("/admin/releases")` (and the other
prefixes) on the router. Streaming raw `Body` is **not** auto-capped —
pass `body_limit(cx)` into `to_bytes`. `to_bytes` now returns
`topcoat::Result<Bytes>` (`ContentTooLargeError` / `BadRequestError`);
drop `BoxError` / `LengthLimitError` maps.

### 7. Import moves (`request` / `response`)

```rust
// 0.5
use topcoat::router::{Body, IntoResponse, Response, ...};

// 0.6
use topcoat::router::{
    Body,
    request::{Bytes, FromRequest, headers, method, uri},
    response::{IntoResponse, Response},
    ...
};
```

Touch at least: `src/app.rs`, `src/tls/access_log.rs` (`Request` /
`Response` / `RouterService`), `src/app/admin/companies/{form,new,company_id}.rs`.
`Body`, `page`, `route`, `error`, `content`, `to_bytes` stay at
`router` root.

`TowerLayer::new` no longer takes a path — use `.at("/api")`.

### 8. `#[memoize]`

```rust
// 0.5 — returned Option<&User> automatically
#[memoize]
async fn session_user(cx: &Cx) -> Option<User> { ... }

// 0.6 — keep that shape
#[memoize(as_ref)]
async fn session_user(cx: &Cx) -> Option<User> { ... }
```

Apply `as_ref` to: `session_user`, `org_context`,
`resolve_org_id_memo`. Count helpers that return `usize` / tuples are
fine. Filter structs used as memo args only need `Hash`.

### 9. `href!` (optional but adopt on the bump)

```rust
use topcoat::router::href;
// in view
<a href=(href!(doc_article_page, Org(slug), Doc(doc)))>
// redirect / mail
Ok(see_other(href!(org_home, Org(slug)).resolve(cx)))
```

Literal path strings still compile. Prefer `href!` for new links and
when touching a redirect. Parameter types need `Display`.

### 10. Views / cookies / Datastar

- `View::render` takes `self` by value. Typical handlers unchanged;
  clone if you render twice. Do not send a rendered `View` across
  threads (arena).
- `class!` of literals is `StaticClass` (`Class<Unescaped<PromotedStr>>`),
  not `Class<Cow<str>>`. VCP rarely names the type.
- Cookie writes after the response is sent **panic** (were silent
  no-ops). Keep `Set-Cookie` in the handler, not a spawned task.
- Multiline Datastar selectors panic (security). VCP does not enable
  `datastar`.

---

## Suggested lots (when implementing)

Do **not** start these until the user asks to bump. One pyramid per lot.

1. **Pin + CLI + assets** — 0.6.2 facade/CLI; Justfile / pkg bundle
   path; compile-clean with mechanical Cx / imports / `path_param!` /
   `memoize(as_ref)` / OriginPolicy. No `href!` yet.
2. **Limits + 404 chrome** — `BodyLimit` on upload prefixes;
   `not_found!("/")`; layout `NotFoundError` branding; unused-layer
   audit.
3. **Adopt** — `href!` on redirects + mail; typed ephemeral path
   params; concurrent-render review of list `for` components; optional
   sitemap.

Keep SSR `?page=N` on `limit`/`offset`/`count` (Toasty). Concurrent
components do **not** replace SQL-side paging.

---

## Out of scope

- `websocket` / `sse` / `datastar` as product surface
- Vendoring `topcoat-ui` (`accordion`, `dialog`, `pagination`, …)
- Switching `src/tls/serve.rs` to `topcoat::start` or Axum+`TowerService`
- Changing SQL of applied Toasty migrations
- Feature `net` / Toasty JSONB (separate stack)

---

## Upstream doc index (tag v0.6.2)

| Source | Use for |
|--------|---------|
| `crates/topcoat/docs/context.md` | `Cx::with`, clone, memoize scope |
| `crates/topcoat/docs/session.md` | Sessions; origin now on the router |
| `crates/topcoat-router/macro/docs/path_param.md` | `path_param!`, catch-all |
| `crates/topcoat-router/macro/docs/not_found.md` | Catch-all 404 pages |
| `crates/topcoat-router/docs/error.md` | Rewrite, 404 branding |
| `crates/topcoat-router/docs/tower.md` | `TowerRoute` vs `TowerService` |
| `crates/topcoat-router/docs/content/sitemap.md` | XML sitemap |
| `crates/topcoat-view/macro/docs/view.md` | Concurrent components |
| `crates/topcoat-core/macro/docs/memoize.md` | Hash key, `as_ref` |
| `crates/topcoat/docs/asset.md` | Exe-adjacent bundle |
| `crates/topcoat-cli/docs/fmt.md` | Formatter + new macros |

When behavior is unclear, **read the tagged guide** in the clone, not
`main`.
