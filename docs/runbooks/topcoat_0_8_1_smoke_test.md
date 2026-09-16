# Topcoat 0.8.1 smoke test

**Audience:** operators staging a VCP build after the 0.8.0 → **0.8.1** pin.
**Severity:** high — default `TrailingSlash::Redirect` 308-resubmits POST
`/login/` and shard `/`; VCP must stay on `TrailingSlash::Strict`.

Successor of [`topcoat_0_8_smoke_test.md`](topcoat_0_8_smoke_test.md).
Re-run that runbook first (runtime script, login cooldown, search morph).
This sheet is the slash / CLI delta only.

## Automated prerequisites

- `just validate` green on the checkout (or at least
  `cargo test --test integration_tests -- http_edge topcoat_0_8 -- --test-threads=1`).
- `topcoat fmt -V` prints `0.8.1` (`just` `ensure-topcoat`).
- Host rustc **1.98**. Runtime script path is unchanged from 0.8.0
  (no `topcoat-runtime` 0.8.1 crate).

## Pass / Fail

| Check | Pass | Fail |
|-------|------|------|
| CLI | `topcoat fmt -V` is **0.8.1** | Stale 0.8.0 CLI |
| Runtime script | View-source on `/login` still includes `/_topcoat/runtime/` | Panic about missing `.runtime()` |
| GET slash | `GET /login/` is **308** to `/login` (VCP `http_canonical`) | 404 or 200 on `/login/` |
| POST slash | `POST /login/` is **404** (not 308, not 200) | Form resubmitted / cooldown skipped |
| Login cooldown | Send magic link; Check-your-email panel still ticks | Panel stuck / 5xx |

## Related

- `.cursor/skills/topcoat/references/UPGRADE-0.8.1.md`
- [`post_forms_smoke_test.md`](post_forms_smoke_test.md) — POST pages,
  rewrite on error, 303 on success (exploit lots)
- [`topcoat_0_8_smoke_test.md`](topcoat_0_8_smoke_test.md)
- `docs/runbooks/http_edge_smoke_test.md`
