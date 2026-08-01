---
name: Topcoat 0.5 migration
overview: Migrate VCP from Topcoat 0.4.0 to 0.5.0 as a mechanical API upgrade (layouts, imports, sessions, CLI fmt), keep the custom HTTPS serve path, then re-run the full relevant test pyramid and update pin notes in skills/docs.
todos:
  - id: bump-pins
    content: Bump Cargo.toml + Justfile + README to topcoat/topcoat-cli 0.5.0; drop signal skip in topcoat-fmt
    status: completed
  - id: migrate-layouts-session
    content: Migrate 4 layouts Slot->Result; SessionConfig import in app.rs
    status: completed
  - id: migrate-imports
    content: Move router error/content imports across ~19 src files + qualified paths
    status: completed
  - id: fix-tls
    content: Compile-fix TLS RouterService / access_log against 0.5
    status: completed
  - id: pyramid-invariants
    content: Pin layout Result (no Slot) in portal_shell check + invariants
    status: completed
  - id: validate-pyramid
    content: fmt, clippy, check_*.sh, focused tests, just validate, smoke runbooks
    status: completed
  - id: sync-skills
    content: Update skill pin notes to VCP on 0.5.0
    status: completed
isProject: false
---

# Topcoat 0.4 → 0.5 migration

Mechanical upgrade only: compile against [v0.5.0](https://github.com/tokio-rs/topcoat/releases/tag/v0.5.0), keep Concept UI + custom TLS. No `websocket` / `sse` / `datastar` / `mail`. Checklist already drafted in [`.cursor/skills/topcoat/references/UPGRADE-0.5.md`](.cursor/skills/topcoat/references/UPGRADE-0.5.md).

```mermaid
flowchart LR
  pins[Bump pins Cargo Justfile]
  code[Layouts imports SessionConfig]
  tls[Compile TLS RouterService]
  fmt[Fmt without signal skip]
  pyramid[Pyramid gates]
  docs[Skills README pin notes]
  pins --> code --> tls --> fmt --> pyramid --> docs
```

## Scope locked

- Bump facade + CLI to **0.5.0** together (`Cargo.toml` deps + build-deps, [`Justfile`](Justfile) `topcoat_cli_version`, [`README.md`](README.md)).
- Keep [`src/tls/serve.rs`](src/tls/serve.rs) / [`src/tls/access_log.rs`](src/tls/access_log.rs) (not `topcoat::start`).
- Do **not** brand 404 in root layout in this PR (downstream of `slot: Result`; separate slice if wanted).
- Do **not** enable new optional features.

## 1. Pins

| File | Change |
|------|--------|
| [`Cargo.toml`](Cargo.toml) | `topcoat = "0.5.0"` (deps + build-deps; same features) |
| [`Justfile`](Justfile) | `topcoat_cli_version := "0.5.0"`; remove signal-file skip in `topcoat-fmt` / comments |
| [`README.md`](README.md) | Document Topcoat / CLI **0.5** |

`cargo update -p topcoat` (or equivalent) so `Cargo.lock` resolves.

## 2. Code migrations (compile blockers)

**Layouts (4):** [`src/app.rs`](src/app.rs), [`src/app/login.rs`](src/app/login.rs), [`src/app/org.rs`](src/app/org.rs), [`src/app/admin.rs`](src/app/admin.rs)

- `slot: Slot<'_>` → `slot: Result`
- `(slot.await?)` → `(slot?)`
- Drop `Slot` import

**Sessions (1):** [`src/app.rs`](src/app.rs)

- `session::{Config as SessionConfig, …}` → `session::{SessionConfig, …}`

**Imports (~19 `src/` files):** move status helpers / `SeeOther` / `RouterErrorExt` → `topcoat::router::error::*`; move `Form` → `topcoat::router::content::*`. Leave `StatusCode`, `Method`, `page`, `route`, `layout`, `path_param`, `query_params` at `router` root. Fix fully-qualified call sites (`topcoat::router::not_found()` → `error::not_found()`).

**Assets:** no `AssetBundle::get` / `.path()` / `hosted_at` in tree — only ensure `asset!` handles stay referenced in root layout (already true).

**TLS:** fix compile breaks in `RouterService` / hyper wiring if 0.5 changed signatures; keep `dev::notify_ready` behavior.

## 3. Tooling after CLI bump

- Reinstall / use `topcoat-cli` 0.5 via `ensure-topcoat`.
- `just topcoat-fmt` formats **all** `src` including signal files (`builds.rs`, `docs.rs`, `issues.rs`, `admin/issues.rs`, `modal.rs`).
- `just fmt` / `fmt-check` must pass without the skip list.

## 4. Pyramid (mandatory)

Treat the upgrade as a behavioral surface change (layouts + redirects + runtime assets). Extend invariants lightly so we do not regress to `Slot`:

- Update [`scripts/check_portal_shell.sh`](scripts/check_portal_shell.sh) + [`tests/integration_tests/portal_shell_invariants_test.rs`](tests/integration_tests/portal_shell_invariants_test.rs) to require layout `slot: Result` (or forbid `Slot<'_>` / `slot.await`) while keeping existing `#[layout]` / `runtime::script` / `asset!` pins.
- Auth redirect call-site pins stay name-based (`see_other` / `redirect`) — refresh only if import-path greps exist.

**Validation order (blocking):**

1. `just fmt` then clippy `-D warnings` (TLS + router first failure signal).
2. Structural: `check_portal_shell.sh` → `check_auth_tenant.sh` → `check_builds_entitlement.sh` → `check_http_edge.sh` → docs/issues shard checks.
3. Focused `just test` filters (serial / threads=1 as today):
   - `portal_shell` (invariants → e2e → battle)
   - `auth_tenant` (307 vs 303)
   - `builds_entitlement` + `topcoat_click` unit helper
   - `docs_search_shard`, `org_issues_search_shard`, `admin_issues_search_shard`
   - `http_edge`
4. `just validate` (full gate).
5. Manual smokes (runbook): portal shell → builds ephemeral (tabs/copy) → shard search → HTTP edge assets `/_topcoat/assets/…`.

No new Playwright gate. If 0.5 renames `data-topcoat-on:click` / hydrate markers, fix [`tests/integration_tests/common/topcoat_click.rs`](tests/integration_tests/common/topcoat_click.rs) + builds e2e asserts.

## 5. Docs / skills after green

- [`topcoat` skill](.cursor/skills/topcoat/SKILL.md) + [`web-stack`](.cursor/skills/web-stack/SKILL.md) + [`quality-assurance`](.cursor/skills/quality-assurance/SKILL.md): mark **VCP pin = 0.5.0**; retire “still on 0.4” / signal-skip wording; keep `UPGRADE-0.5.md` as historical checklist.
- Optional plan artifact under `.cursor/plans/` only if you want a dated record (skills already carry the procedure).

## Out of scope

- Mail / Datastar / SSE / WebSocket
- Branded error pages in layouts
- Switching off custom TLS
- Topcoat UI vendoring
