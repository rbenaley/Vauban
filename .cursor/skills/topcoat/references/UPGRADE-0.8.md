# Upgrade Topcoat 0.6.2 → 0.8.0 (VCP playbook)

**Status:** done. VCP pins **0.8.0** (`Cargo.toml` /
`Justfile` `topcoat_cli_version`) on rustc **1.98**.
Next patch: **0.8.1** (done) — [`UPGRADE-0.8.1.md`](UPGRADE-0.8.1.md).

Upstream (no 0.6.3; jump is 0.6.2 → 0.7.0 → 0.8.0):

- [v0.7.0](https://github.com/tokio-rs/topcoat/releases/tag/v0.7.0)
  (2026-09-05) — streaming SSR, lazy `View`, `live!` / `emit!`,
  `suspense` / `error_boundary`, layout `Slot<'_>`
- [v0.8.0](https://github.com/tokio-rs/topcoat/releases/tag/v0.8.0)
  (2026-09-09) — `signal(cx, init)` function, tracked server reads,
  morph, `.runtime()`, `Signal<T>` shard params

Studied tree: temporary clone `/tmp/topcoat-0.8-study` at tag **v0.8.0**
(`149f0de`). Facade docs: `crates/topcoat/CHANGELOG.md`,
`crates/topcoat/docs/{runtime,router,view,asset}.md`, `AGENTS.md`.
Source map:
[tokio-rs/topcoat@v0.8.0](https://github.com/tokio-rs/topcoat/tree/v0.8.0).

Bump target: **0.8.0** (not 0.7.0). 0.8 is the current upstream; landing
on 0.7 would force a second signal/runtime rewrite immediately.

Historical: 0.4→0.5 (`UPGRADE-0.5.md`), 0.5→0.6.2 (`UPGRADE-0.6.md`,
**done**). Do not re-apply those playbooks.

---

## Pins to bump together

| Location | Change |
|----------|--------|
| Host rustc | **MSRV 1.98** (Topcoat 0.7+). VCP `Cargo.toml` is `1.98`. |
| `Cargo.toml` facade | `topcoat = "0.8.0"` (keep `tailwind`, `font-fontsource`, `mail`, `mail-smtp`, `multipart`) |
| `Justfile` | `topcoat_cli_version := "0.8.0"` |
| Host CLI | `cargo install topcoat-cli --version 0.8.0` (or `ensure-topcoat`) |
| `rust-version` | `"1.98"` in `Cargo.toml` + rust-best-practices MSRV note |

**CLI first**, same rule as 0.6: crate and CLI must match. Asset bundle
layout did **not** move again (still exe-adjacent since 0.6).

**Do not enable:** `websocket`, `sse`, `datastar`, `htmx`, `alpine-ajax`,
`ui` (Concept `vb-*` stays). `mail!` is unchanged in 0.7/0.8.

---

## Two breaking waves (both required)

```text
0.6.2  --0.7-->  lazy View + layouts   --0.8-->  signal() + .runtime()
```

### Wave A — 0.7 (will not compile until done)

| 0.6.2 (VCP today) | 0.8.0 |
|-------------------|--------|
| `async fn page(cx: &Cx) -> Result { view! { … } }` | `-> Result<impl View>` and `Ok(view! { … })`. Drop `?` after `view!`. Import `topcoat::view::View`. |
| Pages that only redirect | `-> Result<()>` |
| `#[layout] … slot: Result` + `match` / `(slot?)` | `slot: Slot<'_>` + wrap `(slot)` in `error_boundary` |
| Child content `child: View` | `#[default] child: Child<'_>` |
| `#[component(boxed)]` | `.boxed()` via `ViewExt` |
| Layout 404 via `downcast_ref` on `slot: Result` | `error_boundary(fallback: \|error\| { … }, (slot))` |

Layouts that must move (`check_portal_shell.sh` pins `slot: Result`
today — flip that pin in the same lot):

- `src/app.rs` `root_layout`
- `src/app/admin.rs` `admin_layout`
- `src/app/org.rs` `org_layout`
- `src/app/login.rs` `login_layout`

Root chrome sketch (branded 404 stays; other errors rethrow):

```rust
use topcoat::{
    Result,
    router::{NotFoundError, Slot, StatusCode},
    view::{View, error_boundary, view},
};

#[layout]
pub(crate) async fn root_layout(slot: Slot<'_>) -> Result<impl View> {
    Ok(view! {
        <!DOCTYPE html>
        <html lang="en">
            <head>
                /* assets + topcoat::runtime::script() + dev::script() */
            </head>
            <body>
                error_boundary(
                    fallback: |error| {
                        if error.downcast_ref::<NotFoundError>().is_none() {
                            return Err(error);
                        }
                        Ok(view! {
                            (StatusCode::NOT_FOUND)
                            branded_404_body()
                        })
                    },
                    (slot)
                )
            </body>
        </html>
    })
}
```

`view!` is **lazy** (like `async move`): values mentioned in the
template **move** into the view. Clone when the same value is needed
after the `view!`. Errors bubble through the tree; catch them with
`error_boundary` / `live!`, not `?` on `view!`.

**Streaming (`live!` / `emit!` / `suspense`):** optional on day one.
Once the first byte is out, status / headers / **cookie writes** are
committed — writing the jar from streamed content **panics**. VCP
session cookies must stay in the non-streamed prefix (root layout head
+ handler before `Ok(view!)`). Do not stream by default; dashboard
tiles already overlap I/O via 0.6 concurrent `#[component]`.

### Wave B — 0.8 (will not compile / will panic at runtime until done)

| 0.6.2 (VCP today) | 0.8.0 |
|-------------------|--------|
| `signal name = value;` inside `view!` | `let name = signal(cx, \|\| value);` **above** `view!`. Type `Signal<T>`. Import `topcoat::runtime::signal`. |
| Enclosing fn without `cx` | Add `cx: &Cx` (pages / layouts / components / shards all accept it). |
| `Router::builder()…discover()` | Add **`.runtime()`** (registers `/_topcoat/runtime/pages/…`). `.discover()` no longer covers the runtime. |
| `topcoat::runtime::script()` | Takes `&Cx`; **panics** if `.runtime()` was omitted. `dev::script()` is unchanged. |
| Shard re-render replaces HTML | **Morph** in place (focus / scroll / typed input survive). Lists that reorder need a stable `id` per item. |
| Signal inside a shard resets on re-render | Identity persists; value is user input on the next run. |

```rust
use topcoat::{Result, context::Cx, runtime::signal, view::{View, view}};

#[component]
async fn faq(cx: &Cx) -> Result<impl View> {
    let open = signal(cx, || false);
    Ok(view! {
        <button @click=$(|_e| open.toggle())>"What is Topcoat?"</button>
        <p :hidden=$(!open.get())>"A full-stack Rust framework."</p>
    })
}
```

Router (VCP `src/app.rs` today has `.discover()` only):

```rust
Router::builder()
    .runtime()   // 0.8 — required before runtime::script()
    .discover()
    // … cookies / sessions / assets / OriginPolicy / BodyLimit …
    .build()
```

**VCP signal statement sites to rewrite** (statement form, ~30):

`src/app/login.rs` (11), `src/app/admin/releases/new.rs`,
`src/app/admin/companies.rs` + `form.rs`, `src/app/admin/issues.rs`,
`src/app/org/{docs,issues,builds}.rs`, `src/app/_components/modal.rs`.

Lint scripts that grep `signal foo =` (`check_admin_releases.sh`,
`check_admin_companies.sh`, `check_builds_entitlement.sh`,
`check_admin_companies_search_shard.sh`) must retarget
`let foo = signal(cx`.

---

## Tracked reads (new 0.8 semantics — security)

`.get()` / `.read()` **outside** `$()` in the body that created the
signal are **tracked**. The page or shard re-runs on the server when
the browser changes that signal; HTML is **morphed** in.

`.get()` **inside** `$()` stays client-only (no server re-run).

`.get_untracked()` / `.read_untracked()` read without subscribing.

**The resumed value is user input.** Validate it the same way as a
shard argument or procedure param. Do **not** treat
`signal(cx, \|\| staff_role)` then `.get()` on the server as an
authorization source.

A shard is now an **optimization boundary** (re-run only that region),
not the only way to get a value to the server. Do not delete the
existing search shards on bump — they already isolate list I/O. Do not
add a tracked `.get()` on a heavy page (dashboard, release compose)
without intending a full re-render.

`Signal<T>` as a shard parameter + `$(limit)` (not `$(limit.get())`)
passes the handle; the shard re-renders only if it tracks the value.

---

## Keep from 0.6 (already done)

`href!`, `path_param!`, `Cx::with`, `OriginPolicy`, `BodyLimit` (2 MiB
default — VCP already raises via `[server] max_request_body_mib`),
`not_found!`, `#[memoize]` / `#[memoize(as_ref)]`,
`too_many_requests` / `service_unavailable`, exe-adjacent assets.

**0.7 additive (safe after compile green):**

| API | VCP use |
|-----|---------|
| `href.is_current(cx)` | Org / admin rail active item (replace hand-rolled path compares in `nav.rs` / `vb_rail` if any). A link without a query stays current while the page is filtered / paginated. |
| Empty `Option<T>` query / form | Blank `?q=` / `?page=` → `None` instead of parse failure. Recheck list `SearchQ` / filter forms. |
| Boolean procedure results | 0.7 fix: JS no longer treats `true`/`false` as thenable. VCP procedures return `f64` (`1.0`/`0.0`) — keep that; do not switch to `bool` without a pyramid. |

**0.8 additive (after Wave B):** morph is automatic; give reorderable
lists a stable `id`. Optional: tracked search on a thin page; keep
heavy lists in shards.

---

## Mechanical lotting (when implementing)

1. **Toolchain + pin** — rustc 1.98, `topcoat` + CLI 0.8.0, `.runtime()`,
   `Result<impl View>` + `Ok(view!)` on every page / layout / component /
   shard (mail components in `src/mail_views.rs` included).
2. **Layouts** — `Slot<'_>` + `error_boundary`; flip
   `scripts/check_portal_shell.sh` and portal-shell invariants.
3. **Signals** — `signal(cx, …)` rewrite + lint retarget; login,
   Publish `pkg_go`, LTS steppers, search query/page, builds modals.
4. **Exploit (thin)** — `href.is_current` on rails; confirm empty
   `Option` query; do **not** invent streaming or tracked reads on
   auth / tenant / billing surfaces in the same lot.

Each lot: `just fmt` + fmt-check + clippy `-D warnings` + matching
`check_*.sh` + focused pyramid (`vcp-test-pyramid.mdc`). Auth / login /
Publish / search shards need denial paths.

---

## Import cheat sheet (0.8)

| Symbol | Path |
|--------|------|
| `View` / `ViewExt` / `view!` | `topcoat::view::{View, ViewExt, view}` |
| `Slot` | `topcoat::router::Slot` |
| `Child` | `topcoat::view::Child` |
| `signal` / `Signal<T>` | `topcoat::runtime::{signal, Signal}` |
| `error_boundary` / `suspense` | `topcoat::view::{error_boundary, suspense}` |
| `live!` / `emit!` | `topcoat::view::{live, emit}` |
| `.runtime()` | `topcoat::runtime::RouterBuilderRuntimeExt` |
| `script(cx)` | `topcoat::runtime::script` |

---

## Forbidden on this bump

| Forbidden | Why |
|-----------|-----|
| Land on 0.7.0 | Immediate second rewrite for 0.8 signals / `.runtime()` |
| Enable `websocket` / `sse` / `datastar` | VCP is HTTPS CRUD |
| Vendor `topcoat-ui` | Concept `vb-*` |
| Stream session / cookie writes | Jar write after commit **panics** |
| Trust server `.get()` of a signal for authZ | User input |
| Tracked `.get()` on dashboard / compose | Full page re-run per keystroke |
| Rewrite list pagination to signal-driven infinite scroll | `list-pagination.mdc` stays `?page=N` + `href!` |
| Invent 0.6 `signal name =` on the 0.8 pin | Will not compile |

---

## Verification (after a future bump)

- `just run` — HTML includes runtime module; no panic about missing
  `.runtime()`.
- Login magic-link signals (cooldown / sending) still tick.
- Publish: `require_active_key` procedure + `vb-pkg-kick` `animationend`.
- Org / admin search shards: typing keeps input focus (morph).
- Multipart uploads still under raised `BodyLimit` (not 413).
- Branded 404 still wraps chrome via `error_boundary`.
- `href.is_current` (if adopted) marks the active rail item on `?page=2`.
