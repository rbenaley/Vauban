# Topcoat runtime playbook (VCP)

Companion to `topcoat` skill §10. Pin: **0.4.x**. Re-verify against
`topcoat-runtime` browser bundle when upgrading.

## Mental model

1. Server renders HTML + comment markers (`::topcoat::signal`,
   `::topcoat::expr::start/end`) and `data-topcoat-*` attributes.
2. `topcoat::runtime::script()` (ES module) walks `document.body` in
   **document order** and wires signals / binds / listeners.
3. Client expressions are a Rust subset lowered to JS surrogates
   (`cx.hydrate(...)`, `Signal.get/set`, bool `.dehydrate()` for `if`).

No WASM. No separate SPA. Prefer this over first-party UI JS.

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
- Do **not** use `this` (not the DOM node when the runtime invokes `s(e)`).

Upstream docs showing `@click="alert('hi')"` are misleading for 0.4:
that form alerts at **bind** time, not on click.

## Signals

```rust
view! { cx =>
    signal open = true;
    signal remaining = 300.0; // prefer f64 for numeric client math
    signal use_curl = false;

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

### Show/hide vs class toggles

Proven in VCP: `:style=$(if cond.get() { "" } else { "display:none" })`
(modal, ephemeral live/expired panels). Use that default for visibility.
Segmented controls may use `:class=$(…)` when the full class string is
swapped; keep a static `class=` only if you understand bind replaces it.

### Countdown / interval without `setInterval`

CSS animation + `@animationiteration` (see builds ephemeral `.vb-eph-tick`):
one tick per second, update `remaining` / `mins` / `secs` / `live` signals.

## PRG vs client state

| Concern | Mechanism |
|---------|-----------|
| Issue / revoke download token | `#[route(POST)]` + DB + `SeeOther` |
| Show panel after mint | SSR from DB row on GET |
| fetch ↔ cURL tab, live countdown, copy | Signals only |
| Absolute URL host | `Config::primary_public_origin()` from `server.public_origins` |

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

## Tooling notes

- `just bundle` / `just run` before tests that need `/_topcoat/assets/…`.
- `topcoat fmt` (0.4) **panics** on files that declare `signal` —
  `just topcoat-fmt` skips them.
- Dev HMR (`just dev` / `topcoat dev`) does not use VCP’s custom TLS
  path; prefer `just run` for HTTPS fidelity.

## Canonical VCP examples (in tree)

| Feature | Files |
|---------|--------|
| Modal dismiss (signal + typed Event) | `src/app/_components/modal.rs` |
| Docs live query | `src/app/org/docs.rs` (`signal query`, `@input`) |
| Ephemeral panel (countdown, tabs, copy) | `src/app/org/builds.rs`, `ephemeral.rs`, `styles.css` (`.vb-eph-*`) |
| Click contract tests | `tests/integration_tests/common/topcoat_click.rs` |
