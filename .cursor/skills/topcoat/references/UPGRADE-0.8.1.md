# Upgrade Topcoat 0.8.0 → 0.8.1 (VCP playbook)

**Status:** done. VCP pins **0.8.1** (`Cargo.toml` facade + build-dep,
`Justfile` `topcoat_cli_version`) on rustc **1.98**. Crate display
version is **0.1.3** after the exploit lots (`0.1.2` at the pin lot;
`CARGO_PKG_VERSION` / `product_label()`).

Upstream: [v0.8.1](https://github.com/tokio-rs/topcoat/releases/tag/v0.8.1)
(tag `v0.8.1` / `e9a6ee8`). Router / cookie patch. Crates.io ships
matching 0.8.1 workspace crates (including runtime / asset); VCP does
**not** change `.runtime()` wiring. MSRV stays **1.98**.

0.6.2→0.8.0 playbook (`UPGRADE-0.8.md`) stays historical. Do not re-apply
it. The pin lot kept routes absolute and pages free of `Err(see_other)`;
the **exploit lots** below (same pin, later PR) adopted both — see
"Exploit lots".

## Pins

| Surface | Value |
|---------|-------|
| Facade + build-dep | `topcoat = "0.8.1"` (keep `tailwind`, `font-fontsource`, `mail`, `mail-smtp`, `multipart`) |
| CLI | `topcoat_cli_version := "0.8.1"` then `just ensure-topcoat` before `topcoat fmt` |
| Router slash | `.trailing_slash(TrailingSlash::Strict)` in `src/app.rs` |
| GET/HEAD 308 | Keep `http_canonical` + `SecurityHeaders` (including `/login///`) |
| VCP crate | `0.1.1` → `0.1.2` (pin lot) → `0.1.3` (exploit lots) |

## Why Strict

Default 0.8.1 `TrailingSlash::Redirect` registers a twin (`Methods::Any`)
and **308-resubmits POST** `/login/` and `/_topcoat/runtime/shards/{id}/`.
VCP invariant: POST with a trailing slash must **not** be rewritten
(`e2e_trailing_slash_post_is_not_308`). Strict restores the 0.8.0 miss
(**404**). GET/HEAD `/login/` stay **308** via the pathless security
layer.

## Out of scope (pin lot)

- Enabling `websocket` / `sse` / `datastar` / `ui`
- Deleting `http_canonical` because Topcoat now has slash twins
- A new `topcoat_0_8_1_*` test tree (extend `http_edge_*` + `topcoat_0_8_*`)

## Exploit lots (done, 2026-09-16)

Retired 0.6-era workarounds and adopted the optional 0.7 / 0.8 / 0.8.1
features on the same pin. Plan: `.cursor/plans/topcoat_0.8.1_exploit_lots_*.plan.md`.

| Lot | Topcoat feature | VCP change | Guard |
|-----|-----------------|------------|-------|
| A | `#[memoize]` hashes borrowed args (0.7 #371) | `src/request_intern.rs` deleted; `org_context(cx, slug: &str)`, `require_perms(cx, role: &str)`, list COUNT memos on `&str` | `check_request_sql_dedup.sh`, `auth_tenant_proptest::prop_memoize_str_keys_*` |
| B | Module-relative routes (0.8.1 #406); typed `path_param!` (0.6) | `#[route(POST)]` / `#[route(POST "./publish")]` everywhere the string only repeated the module path; `path_param!(pub(crate) release_id: u64, error = not_found)` + `ReleaseId(id)` markers | `topcoat_0_8_invariants::inv_route_paths_are_module_relative_outside_whitelist` |
| C | `#[page(POST)]` + `SeeOther` as page error (0.8.1 #398, cookies on error #408) | Company create / update are pages: validation re-renders under `root_layout` + `admin_layout`, success `Err(see_other(...))`; `render_admin_page` / `company_form_response` deleted; `/choose-org` is `src/app/choose_org.rs` | `check_admin_companies.sh`, `admin_companies_invariants::inv_company_post_handlers_are_pages_not_response_routes` |
| D | `rewrite` (0.6 #347) | Failed release create / key enrol / key revoke re-run the hosting page as GET via `http_canonical::rewrite_get_with_flash`; success stays 303 PRG | `check_http_edge.sh`, `check_admin_releases.sh`, `check_storage.sh` |
| E | `try_endpoint` (0.6 #318) | `nav_from_cx` maps the matched **pattern** (`/{org}/docs/{doc}`) — slug values never pick the section; request path only on 404 | `check_portal_shell.sh`, `portal_shell_proptest::prop_pattern_nav_*` |
| F | Morph (0.8), bool procedures (0.7 #375) | `row_dom_id(prefix, key)` on every shard row; `request_login_link` / `require_active_key` return `Result<bool>` (wire `true` / `false`) | shard `*_invariants`, `magic_link_invariants`, `check_admin_releases.sh` |
| G | `suspense` (0.7) | **No-go**: dashboard tiles cost ~2 ms in-process (p50 3.0 ms vs 1.05 ms light page); streaming complexity not worth it | `dashboard_stats_invariants::inv_dashboard_render_path_has_no_cookie_writes_and_no_streaming` |

### Rewrite gotchas (learned the hard way)

- Topcoat refuses a rewrite whose target `path?query` was already
  dispatched in the same request (`RewriteLoopError`, 500). A same-URL
  form must target the page href **with** its error query — which is
  also how the GET page reads the code. `rewrite_get_with_flash` asserts
  the `?` in debug builds.
- A pathless layer that converts every `Err` into a response (VCP
  `SecurityHeaders`) swallows the rewrite. It must `return Err(error)`
  when `error.downcast_ref::<RewriteError>().is_some()`; the router
  re-dispatches and the layer runs again on the new dispatch.
- Browser URL stays the POST target; F5 re-submits (standard for errors
  rendered on POST). Success paths keep 303 PRG for that reason.

### View scoping (0.7+ arena)

A `view!` built inside a page render is **scoped** to that build. A
`Mail` html handle created from a `#[page(POST)]` body renders fine at
delivery (inside the request) but panics if rendered after the response
("nested handle rendered outside the build"). Test captures must render
at send time: `tests/.../common::RenderedMemoryTransport`.

## Verify

`just validate`. Smoke: `docs/runbooks/topcoat_0_8_1_smoke_test.md` and
`docs/runbooks/post_forms_smoke_test.md`.
