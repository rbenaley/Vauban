---
name: Browser tz cookie setter
overview: Le formatage local existe déjà (`browser_tz` + `format_unix_local`), mais sans cookie `vcp_tz` le serveur retombe sur UTC. Brancher un petit script first-party qui pose le cookie IANA du navigateur et recharger une fois pour que tout l’HTML authentifié s’affiche dans la zone locale (ex. Europe/Brussels).
todos:
  - id: tz-js-asset
    content: Add assets/vcp_tz.js + wire asset! script in root_layout
    status: completed
  - id: tz-pyramid
    content: Extend check_display_tz + invariants/e2e for cookie setter; fmt/clippy/tests
    status: completed
isProject: false
---

# Browser timezone cookie (`vcp_tz`) end-to-end

## Diagnosis

- Pages already call `browser_tz(cx)` + `format_unix_local` (e.g. [`src/app/org/docs/doc.rs`](src/app/org/docs/doc.rs)).
- [`src/tz.rs`](src/tz.rs): cookie absent → `Tz::UTC` → visible `… UTC`.
- **Missing piece**: nothing in the browser ever sets `vcp_tz`. E2E tests inject the cookie manually; real browsers never get it.

Bruxelles → IANA `Europe/Brussels` (CEST = UTC+2 in summer) once the cookie is set.

## Approach (locked)

1. Add [`assets/vcp_tz.js`](assets/vcp_tz.js): read `Intl.DateTimeFormat().resolvedOptions().timeZone`, write first-party cookie `vcp_tz` (`path=/`, `Max-Age=1y`, `SameSite=Lax`, `Secure` when HTTPS). If the cookie was missing or changed, `location.reload()` once so SSR picks it up.
2. Register via Topcoat `asset!("assets/vcp_tz.js")` and include `<script src=… defer>` in root layout [`src/app.rs`](src/app.rs) (after favicons / before body content is fine; `defer` keeps parse order clean). No `unsafe-inline`.
3. Keep all wall-clock HTML on existing helpers; do not client-format dates.
4. Extend [`scripts/check_display_tz.sh`](scripts/check_display_tz.sh) + display_tz pyramid: pin script asset + layout include; e2e that a response without cookie can still be localized after cookie is present (existing Paris/UTC e2e stays); unit/invariant that script sets `VCP_TZ_COOKIE` name.

## Surfaces already covered (no change beyond cookie)

| Surface | Helper |
|---------|--------|
| Client/admin docs timestamps | `format_unix_local` |
| Issues meta / relative | `format_unix_local` / `format_relative` |
| Dashboard doc activity | `format_unix_local` |

Date-only fields (`Release.released_on` as `YYYY-MM-DD`) stay as calendar strings (no wall-clock).

## Validation

`rtk cargo fmt`, clippy `-D warnings`, `bash scripts/check_display_tz.sh`, `rtk cargo test --test integration_tests -- display_tz -- --test-threads=1`. Manual: hard-refresh docs modal → expect `CEST` / `Europe/Brussels` style zone label after first reload (e.g. `2026-07-27 16:17 CEST`).
