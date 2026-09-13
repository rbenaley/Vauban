# Topcoat 0.8 smoke test

**Audience:** operators staging a VCP build on Topcoat **0.8.0**.
**Severity:** high — omitting `.runtime()` panics HTML, and a stale CLI
breaks `view!` / asset ids.

Successor of [`topcoat_0_6_smoke_test.md`](topcoat_0_6_smoke_test.md).
Keep the 0.6 checks (body cap, `href!`, OriginPolicy) and add the 0.8
runtime / morph / layout pins.

## Automated prerequisites

- `just validate` green on the checkout (or at least
  `cargo test --test integration_tests -- topcoat_0_8 -- --test-threads=1`
  plus `topcoat_0_6` / `magic_link` / `auth_tenant` / `portal_shell` /
  `admin_releases` / search shards / `builds_entitlement`).
- `topcoat fmt -V` prints `0.8.0` (`just` `ensure-topcoat`).
- Host rustc **1.98** (`Cargo.toml` `rust-version`, tahoe `pkg lock rust`).
- Config has `[server] max_request_body_mib` (default **2048**).

## Pass / Fail

| Check | Pass | Fail |
|-------|------|------|
| Runtime script | View-source on `/login` includes `/_topcoat/runtime/` | Panic about missing `.runtime()` |
| Login cooldown | Send magic link; Check-your-email panel ticks without a full reload | Panel stuck / 5xx |
| Search morph | Org docs search: typed query and caret survive the shard morph | Focus jumps / input cleared |
| Publish idle | `/admin/releases/new` Publish enable path + `vb-pkg-kick` idle tick | Button dead / missing kick class |
| 404 chrome | `GET /no-such-page` is **404** with branded chrome | Bare `not found` text |
| List rail | `/{org}/docs?page=2` keeps the Docs rail item active | Rail highlight lost on query |
| Pkg upload | Admin New release with a real `.pkg` is not **413** | Raise `max_request_body_mib` |

## Related

- `.cursor/skills/topcoat/references/UPGRADE-0.8.md`
- [`topcoat_0_6_smoke_test.md`](topcoat_0_6_smoke_test.md)
- `docs/runbooks/http_edge_smoke_test.md`
