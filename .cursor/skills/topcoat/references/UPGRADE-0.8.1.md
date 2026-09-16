# Upgrade Topcoat 0.8.0 → 0.8.1 (VCP playbook)

**Status:** done. VCP pins **0.8.1** (`Cargo.toml` facade + build-dep,
`Justfile` `topcoat_cli_version`) on rustc **1.98**. Crate display
version is **0.1.2** (`CARGO_PKG_VERSION` / `product_label()`).

Upstream: [v0.8.1](https://github.com/tokio-rs/topcoat/releases/tag/v0.8.1)
(tag `v0.8.1` / `e9a6ee8`). Router / cookie patch. Crates.io ships
matching 0.8.1 workspace crates (including runtime / asset); VCP does
**not** change `.runtime()` wiring. MSRV stays **1.98**.

0.6.2→0.8.0 playbook (`UPGRADE-0.8.md`) stays historical. Do not re-apply
it. Do **not** convert routes to `./` or pages to `Err(see_other)`.

## Pins

| Surface | Value |
|---------|-------|
| Facade + build-dep | `topcoat = "0.8.1"` (keep `tailwind`, `font-fontsource`, `mail`, `mail-smtp`, `multipart`) |
| CLI | `topcoat_cli_version := "0.8.1"` then `just ensure-topcoat` before `topcoat fmt` |
| Router slash | `.trailing_slash(TrailingSlash::Strict)` in `src/app.rs` |
| GET/HEAD 308 | Keep `http_canonical` + `SecurityHeaders` (including `/login///`) |
| VCP crate | `0.1.1` → `0.1.2` |

## Why Strict

Default 0.8.1 `TrailingSlash::Redirect` registers a twin (`Methods::Any`)
and **308-resubmits POST** `/login/` and `/_topcoat/runtime/shards/{id}/`.
VCP invariant: POST with a trailing slash must **not** be rewritten
(`e2e_trailing_slash_post_is_not_308`). Strict restores the 0.8.0 miss
(**404**). GET/HEAD `/login/` stay **308** via the pathless security
layer.

## Out of scope

- Relative `./` route paths
- `SeeOther` as a page `Err` / navigation style
- Enabling `websocket` / `sse` / `datastar` / `ui`
- Deleting `http_canonical` because Topcoat now has slash twins
- A new `topcoat_0_8_1_*` test tree (extend `http_edge_*` + `topcoat_0_8_*`)

## Verify

`just validate`. Smoke: `docs/runbooks/topcoat_0_8_1_smoke_test.md`.
