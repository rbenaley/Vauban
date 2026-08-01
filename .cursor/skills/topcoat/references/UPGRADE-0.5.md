# Upgrade Topcoat 0.4 → 0.5 (VCP) — historical

Companion to the `topcoat` skill. Upstream source of truth:
[v0.5.0 release notes](https://github.com/tokio-rs/topcoat/releases/tag/v0.5.0).

**Status:** VCP completed this upgrade (pin **0.5.0**). Keep this file as
the checklist / rationale for the breaking moves. Do not re-apply on a
tree that is already on 0.5.

## Pins to bump together

| Location | Change |
|----------|--------|
| `Cargo.toml` facade | `topcoat = "0.5.0"` (+ same features; `serve` is default) |
| `Justfile` | `topcoat_cli_version := "0.5.0"` |
| README / docs | Note CLI + facade version |

After CLI bump: remove the `signal`-file skip in `just topcoat-fmt` if
present — **0.5** formats `signal` decls (and `mail!`).

## Mechanical code migrations

### 1. Layouts

```rust
// Before (0.4)
#[layout]
async fn shell(slot: Slot<'_>) -> Result {
    view! { <main>(slot.await?)</main> }
}

// After (0.5)
#[layout]
async fn shell(slot: Result) -> Result {
    view! { <main>(slot?)</main> }
}
```

Drop `use topcoat::router::Slot`. Touch every layout: root, login, org,
admin, …

Optional follow-up: brand 404/403 in the root layout via
`error.downcast_ref::<NotFoundError>()` (see upstream `error.md`).

### 2. Import moves

| Old (`topcoat::router::…`) | New |
|----------------------------|-----|
| `not_found`, `see_other`, `forbidden`, `redirect`, `unauthorized`, … | `router::error::…` |
| `SeeOther`, `RouterErrorExt`, error types | `router::error::…` |
| `Form`, `Html`, `Json`, `Css`, `RawForm` | `router::content::…` |
| `Multipart` | `router::content::multipart::Multipart` |
| `TowerLayer` | `router::tower::TowerLayer` |

`StatusCode`, `Method`, `page`, `route`, `layout`, `path_param`,
`query_params` stay at `router` root (confirm against the pin).

### 3. Sessions

Upstream renamed `session::Config` → `session::SessionConfig` (and the
builder). VCP on 0.4 already aliases:

```rust
use topcoat::session::{Config as SessionConfig, …};
```

On 0.5, drop the alias and import `SessionConfig` directly:

```rust
use topcoat::session::{SessionConfig, RouterBuilderSessionExt};
```

### 4. Assets

`AssetBundle::empty()` is gone. VCP fails closed on missing/stale bundles
(`load_assets` + `require_catalog_assets`). Tailwind's `asset!` path
includes `OUT_DIR`, so always rebundle after rebuild (`just run` /
`just bundle`); bare `cargo run` after a rebuild panics resolving CSS.

#### Manual bundle lookups (only if looking up by hand)

```rust
// Before
bundle.get(LOGO)
bundle.get(LOGO).unwrap().path()

// After
bundle.get(LOGO.id())
bundle.dir().join(bundle.get(LOGO.id()).unwrap().name())
```

Rendering `src=(LOGO)` in `view!` is unchanged. Ensure every `asset!`
handle is **used** (otherwise the linker may drop the declaration and
the bundler will miss it).

`AssetConfig::hosted_at` arg order: **`(base_url, manifest)`**.

### 5. HTML snapshots / asserts

Boolean attributes: `disabled="true"` → `disabled=""`. Grep tests and
`check_*.sh` for the old spelling.

### 6. Features / serve

Default features already include `serve`. Only builds with
`default-features = false` must add `serve` next to `router` if they
call `topcoat::serve` / `start`. VCP’s custom TLS path still uses the
router service — re-verify `src/tls/serve.rs` compiles against 0.5
`Listener` / `RouterService` APIs.

## Validation after upgrade

Follow `quality-assurance`:

1. `just fmt` (expect signal files to format under 0.5 CLI)
2. `just clippy` / `just validate`
3. Focused pyramid filters for layouts, redirects, builds ephemeral
   (signals / `@click`), asset probes
4. Smoke: login, org chrome, docs/issues shards, builds mint panel

## Out of scope unless product asks

- Enabling `websocket`, `sse`, `datastar`
- Adopting `topcoat-mail` (useful later for invites / password reset)
- Switching from custom HTTPS to `topcoat::start`
- Vendoring `topcoat ui`
