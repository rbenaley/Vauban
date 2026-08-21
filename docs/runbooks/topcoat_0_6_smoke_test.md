# Topcoat 0.6 smoke test

**Audience:** operators staging a VCP build on Topcoat **0.6.2**.
**Severity:** high — a stale CLI or a too-small HTTP body cap breaks HTML
assets and pkg publish.

## Automated prerequisites

- `just validate` green on the checkout (or at least
  `cargo test --test integration_tests -- topcoat_0_6 -- --test-threads=1`
  plus `admin_releases` / `storage_` / `portal_issues` / `auth_tenant`).
- `topcoat fmt -V` prints `0.6.2` (`just` `ensure-topcoat`).
- Config has `[server] max_request_body_mib` (default **2048**) and it is
  `>=` helper `max_artifact_bytes` / `max_image_bytes` (in MiB).

## Pass / Fail

| Check | Pass | Fail |
|-------|------|------|
| Login HTML | `/login` 200 with Tailwind / runtime script URLs | Panic `asset catalog is stale` or missing CSS |
| Bundle path | `target/debug/assets/manifest.toml` (or `target/release/assets`) after `just bundle` | Bundle only in old `target/assets` and HTML 500 |
| Pkg publish | Admin New release with a real `.pkg` PRGs to the list | **413** — raise `max_request_body_mib` or fix helper quotas |
| CSRF | Cross-origin POST to a mutation is 403 | 200 / redirect without OriginPolicy |
| 404 chrome | `GET /no-such-page` is **404** with `data-vcp-404` + document chrome; `/{org}/no-such` keeps `vb-shell` | Bare `not found` text, no layout |
| Ephemeral URL | `GET /releases/{token}/{pkg}` still streams the pkg after generate | 404 / wrong segment parse |
| Client click-through | After login, Home → Docs → Issues → Account; every in-app `<a href>` is a portal path (no raw typed URLs drifting from routes) | Broken link or 404 on a rail item |
| Admin click-through | Releases list → New release (or confirm) and Companies list → New company; PRG `Location` matches the list/edit page | 303 to a hand-written stale path |

## Related

- `.cursor/skills/topcoat/references/UPGRADE-0.6.md`
- `docs/runbooks/http_edge_smoke_test.md` (asset cache headers)
- `docs/runbooks/freebsd_pkg_smoke_test.md` (packaged `share/vcp/assets`)
