# Topcoat runtime playbook (VCP)

Companion to `topcoat` skill §10. VCP pins Topcoat **0.6.2**; re-verify
the browser bundle when bumping the facade. Historical 0.4→0.5 /
0.5→0.6 notes: `UPGRADE-0.5.md`, `UPGRADE-0.6.md` (0.6.1 lets `await`
appear inside `$()` `ExprBlock` / `ExprIf`). Next bump (not pinned):
`UPGRADE-0.8.md` — `signal(cx, init)`, `.runtime()`, layout
`error_boundary`. Write 0.6.2 forms until then.

## Mental model

1. Server renders HTML + comment markers (`::topcoat::signal`,
   `::topcoat::expr::start/end`) and `data-topcoat-*` attributes.
2. `topcoat::runtime::script()` (ES module asset, renamed `topcoat` in
   the bundle) walks `document.body` in **document order** and wires
   signals / binds / listeners.
3. Client expressions are a Rust subset lowered to JS surrogates
   (`cx.hydrate(...)`, `Signal.get/set`, bool `.dehydrate()` for `if`).

No WASM on the client. No separate SPA. Prefer this over first-party UI JS.

**0.6 server-side:** `#[component]` siblings in one `view!` render
concurrently (I/O overlaps). That is HTML generation, not the browser
runtime. Do not assume sequential DB calls inside a loop of
components — see `UPGRADE-0.6.md`. 0.6.1 also allows `await` inside
`$()` blocks / `if` expressions.

**VCP example:** org dashboard tiles (`src/app/org.rs` +
`src/app/org/dashboard_tiles.rs`) are sibling components that share
`#[memoize]` loaders (one `Issue::all()`, entitled releases, published
docs). Concurrent callers share the in-flight future — do not split
issue tiles into per-status SQL `COUNT`.

**Publish compose:** `require_active_key` is a `#[procedure]` called from
`@submit=$(async …)` (same pattern as login `request_login_link`).
`POST /admin/releases/new/validate-pkg` stays a Multipart route — file
bytes are not procedure args. Interpolate that URL with `href!` (e.g.
`data-validate-pkg`); do not `fetch` `/admin/releases/new/require-active-key`.
FormData lives in a raw `@animationend` on a one-shot `vb-pkg-kick` tick
(kicked by `pkg_go` after the procedure). Do **not** hang that preflight
on `@animationiteration` with `animation-iteration-count: 1` — that event
never fires, and Publish looks like a no-op. `$()` `return` after `await`
is compiled into a nested IIFE; put `pkg_go.set(true)` in `else`, not
after `return`.

## `@click` / `@*` bind contract (critical)

```js
// topcoat-runtime (simplified)
const s = new Function("cx", `return ${attr.value}`)(runtime.context);
el.addEventListener(name, (native) => s(wrap(native)));
```

| Attribute value | Bind-time behavior | Click-time |
|-----------------|--------------------|------------|
| `(() => { … return (e) => … })()` from `$()` | Returns handler fn | Calls handler |
| `(e) => { … }` raw string | Returns handler fn | Calls handler |
| `navigator.clipboard…; this.textContent=…` | **Executes now**; often throws on `this` | Never reached if scan aborted |

A throw inside the attribute loop **stops scanning** that element’s
remaining attrs and can leave **later elements unhydrated**. Symptom:
countdown (earlier in DOM) works; fetch/cURL tabs (later) do nothing.

### Clipboard pattern (VCP)

`$()` cannot call `navigator.clipboard`. Use a **function** string:

```rust
@click="(e) => { const el = e.current_target.inner; navigator.clipboard.writeText(el.getAttribute('data-copy')); el.textContent = 'Copied'; }"
```

- Handler receives Topcoat `Event` wrapper (`current_target` → element
  surrogate with `.inner` = real `Element`).
- Do not use `this` (not the DOM node when the runtime invokes `s(e)`).

Upstream examples that use bare statements in `@click` (e.g.
`alert('hi')`) are misleading: that form runs at **bind** time, not on
click.

## Signals

```rust
view! { cx =>
    let open = signal(cx, || true);
    let remaining = signal(cx, || 300.0); // prefer f64 for numeric client math
    let use_curl = signal(cx, || false);

    <div :style=$(if open.get() { "" } else { "display: none" })>
        …
    </div>
    <button type="button" @click=$(|e: Event| {
        e.prevent_default();
        open.set(false);
    })>"Close"</button>
}
```

- Writes (`set`) panic if evaluated server-side — only in `@` / client
  `$()` paths.
- Text `$(if sig.get() { "a" } else { "b" })` emits comment markers; the
  runtime **skips the first** client patch (keeps SSR text) then updates
  on later signal changes.
- `:attr=$(...)` always applies on first client run (including `:class`,
  `:style`, `:data-copy`).
- **0.5+ shorthands:** `bool` → `toggle()`; `f64` → `increment()` /
  `decrement()`; `String` → `push_str(...)`. Prefer these over
  `set(get() ± 1)`.

### Show/hide vs class toggles

Proven in VCP: `:style=$(if cond.get() { "" } else { "display:none" })`
(modal, ephemeral live/expired panels). Use that default for visibility.
Segmented controls may use `:class=$(…)` when the full class string is
swapped; keep a static `class=` only if you understand bind replaces it.

### Countdown / interval without `setInterval`

CSS animation + `@animationiteration` (`.vb-eph-tick`) paces the UI about
once per second **while visible**. Animations pause off-focus, so never
`remaining -= 1`. Seed `data-expires-at` (unix) and recompute with
`Date.now()` in a raw handler ( `$()` cannot call `Date.now` ). See builds
ephemeral panel.

## Shards and path params

Shard POSTs hit `/_topcoat/runtime/shards/{id}` — **not** the page URL. There is
no `{org}` (or other page path param) on that route. Calling
`path_param::<Org>(cx)` inside a `#[shard]` **panics** at runtime.

Pass tenant / ids as **shard arguments** from the page (`$(org.clone())`)
and re-check with `require_org` / Casbin. Never read page path params in
shard handlers.

Admin shards also skip the page layout: re-run `require_staff` (and the
relevant Casbin check) inside the `#[shard]` before loading data.

## Redirects (idiomatic)

Prefer Topcoat helpers — do not hand-roll status + `Location` unless a
helper truly cannot express the need (document why if so).

Import helpers from `topcoat::router::error::{…}`.

| Helper | Status | Pattern |
|--------|--------|---------|
| `see_other(uri)` | 303 | PRG after successful POST/PUT/DELETE → `Ok(see_other(...))` |
| `redirect(uri)` | 307 | Temporary navigational GET (hubs, aliases) → `Err(redirect(...).into())` |
| `redirect_permanent(uri)` | 308 | Permanent / canonical URL → same `Err(...).into()` or `IntoResponse` in a layer |

Trailing-slash canonicalization (VCP):

- Pure helper: `http_canonical::trailing_slash_redirect_location`
- Safe methods only (`GET` / `HEAD`) via `should_redirect_trailing_slash`
- Pathless `Layer` (`path() -> None`, registered with `.layer(...)`) calls
  `redirect_permanent(&location).into_response(&cx)?`
- Do **not** use `MOVED_PERMANENTLY` (301) when `redirect_permanent` fits
- Do **not** use `#[layer]` in `src/app.rs` for this: 0.6 scopes it to `/`
  and skips unmatched `/login/`

In a pathless layer, convert with `IntoResponse` so security headers can still
be applied to the redirect response before returning `Ok(response)`.
Do **not** `?`-propagate `next.run(...).await` when the layer must decorate
responses: handler `Err(redirect(...))` would skip header application.
Convert `Err(error) => error.into_response(cx)?` first, then mutate headers.

## PRG vs client state

| Concern | Mechanism |
|---------|-----------|
| Issue / revoke download token | `#[route(POST)]` + DB + `see_other` (303) |
| Show panel after mint | SSR from DB row on GET |
| Docs / issues list filter (no mutation) | `method="GET"` form + optional live `#[shard]` |
| fetch ↔ cURL tab, live countdown, copy | Signals only |
| Absolute URL host | `Config::primary_public_origin()` from `server.public_origins` |
| Trailing slash / renamed path | `redirect_permanent` (308) in edge layer or handler |

Never generate security tokens in the browser. Never use `?tool=` (or
similar) just to switch a tab the client can own.

## `app_context` for config

```rust
// router
.app_context(Arc::new(cfg.clone()))

// pages
let origin = auth::config(cx).primary_public_origin();
```

Validate `public_origins` non-empty + HTTPS-only at boot.

## Testing

| Layer | What to assert |
|-------|----------------|
| Invariants / `check_*.sh` | Source pins: `signal …`, `use_curl.set`, no bind-time clipboard stmts, no custom eph JS |
| Unit (`topcoat_click`) | Handler strings are function expressions |
| E2E | SSR HTML contains `data-topcoat-on:click` + `hydrate(true/false)` + `current_target`; run `assert_topcoat_click_handlers_are_functions` on the panel fragment |
| Smoke runbook | Human clicks tabs / copy in a real browser |

There is **no** Playwright/WKWebView gate in CI. Do not invent one unless
the project explicitly adds a browser runner.

## Current pin (0.8.0)

- Declare signals above `view!`: `let name = signal(cx, || value);`.
- Call `.runtime()` on the router builder or `runtime::script()` panics.
- Layouts wrap `(slot)` in `error_boundary`; param is `Slot<'_>`.
- Re-renders **morph**; reorderable lists need a stable `id`.
- Server `.get()` outside `$()` is a **tracked** read (user input).
  Never authZ / role / tenant from a tracked read.

## Tooling notes

- `just bundle` / `just run` before tests that need `/_topcoat/assets/…`.
- **`topcoat fmt`:** formats `signal` declarations; `--stdin` exits
  non-zero on format failure. `just topcoat-fmt` covers all `src` Rust
  files. `topcoat dev` reports cargo stderr on build failures.
- Dev HMR (`just dev` / `topcoat dev`) does not use VCP’s custom TLS
  path; prefer `just run` for HTTPS fidelity.

## Canonical VCP examples (in tree)

| Feature | Files |
|---------|--------|
| Modal dismiss (signal + typed Event) | `src/app/_components/modal.rs` |
| Docs live query | `src/app/org/docs.rs` (`let query = signal(cx, …)`, `@input`) |
| Ephemeral panel (countdown, tabs, copy) | `src/app/org/builds.rs`, `ephemeral.rs`, `styles.css` (`.vb-eph-*`) |
| Click contract tests | `tests/integration_tests/common/topcoat_click.rs` |
