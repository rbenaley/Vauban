---
name: Topcoat 0.8.1 bump
overview: "Thin no-regression pin from Topcoat 0.8.0 to 0.8.1: matching CLI, TrailingSlash::Strict so POST slash stays 404, keep VCP GET/HEAD 308 via http_canonical, bump the VCP crate 0.1.N to 0.1.N+1 (today 0.1.1 -> 0.1.2). Extend the existing http_edge and topcoat_0_8 pyramids — no new harness, no ./ paths, no SeeOther-on-page."
todos:
  - id: gate0-baseline
    content: "Gate 0: just validate on 0.8.0 before any pin edit"
    status: completed
  - id: lot1-pin-strict
    content: Bump facade+CLI to 0.8.1, crate 0.1.N to 0.1.N+1 (0.1.1 -> 0.1.2), TrailingSlash::Strict, flip check_topcoat_0_8.sh + 0.8 invariants
    status: completed
  - id: pyramid-extend
    content: Extend http_edge + topcoat_0_8 (invariants, proptest POST no-308, battle POST slash, e2e 404, shard+/ 404); smoke line; just validate
    status: completed
  - id: browser-verify
    content: "Browser: GET /login/ 308, POST /login/ not resubmitted, login cooldown still ticks"
    status: completed
  - id: docs-skills
    content: UPGRADE-0.8.1.md done + SKILL/web-stack pin 0.8.1; do not rewrite the 0.8.0 plan
    status: completed
isProject: false
---

# Topcoat 0.8.0 to 0.8.1 (no-regression)

Follow the 0.8.1 study (`/tmp/topcoat-0.8.1-study`, tag `v0.8.1` / `e9a6ee8`) and [release notes](https://github.com/tokio-rs/topcoat/releases/tag/v0.8.1). VCP pin today: `topcoat = "0.8.0"` in [`Cargo.toml`](Cargo.toml) (facade + build-dep), `topcoat_cli_version := "0.8.0"` in [`Justfile`](Justfile). Runtime is unchanged (no `topcoat-runtime` 0.8.1 entry). MSRV stays **1.98**.

**Scope (locked):** pin + CLI + `.trailing_slash(TrailingSlash::Strict)` + crate patch **0.1.N → 0.1.N+1**. Keep [`src/http_canonical.rs`](src/http_canonical.rs) + [`SecurityHeaders`](src/app.rs) for GET/HEAD 308 (including `/login///`). Do **not** convert routes to `./` or pages to `Err(see_other)`. Do **not** enable `websocket` / `sse` / `datastar` / `ui`. Do **not** edit [`.cursor/plans/topcoat_0.8.0_upgrade_96e5748b.plan.md`](.cursor/plans/topcoat_0.8.0_upgrade_96e5748b.plan.md).

```mermaid
flowchart LR
  baseline[Gate0_validate_0_8_0]
  pin[Pin_0_8_1_plus_Strict]
  pyramid[Extend_http_edge_and_topcoat_0_8]
  docs[Skills_and_runbook]
  baseline --> pin --> pyramid --> docs
```

## Why Strict

Default 0.8.1 `TrailingSlash::Redirect` registers a twin route (`Methods::Any`) and 308-resubmits **POST** `/login/` (and `/_topcoat/runtime/shards/{id}/`) to the declared form. VCP’s invariant is the opposite: POST with a trailing slash must **not** be rewritten ([`e2e_trailing_slash_post_is_not_308`](tests/integration_tests/http_edge_e2e_test.rs)). Strict restores the 0.8.0 miss (404). GET/HEAD `/login/` stay 308 via the pathless security layer (Topcoat twins never see `///` anyway).

In [`src/app.rs`](src/app.rs) `router_with_mail`, after `.origin_policy(...)` (or immediately before `.build()`):

```rust
.trailing_slash(topcoat::router::TrailingSlash::Strict)
```

## Gate 0 — still 0.8.0

`just validate` green before any pin edit. If red, stop.

## Lot 1 — pins + Strict (one compile-green slice)

Bump together:

- [`Cargo.toml`](Cargo.toml) `[package] version` **0.1.N → 0.1.N+1** (today `0.1.1` → `0.1.2`). Align example comments / runbook that hardcode the display line (`VCP — v0.1.N [hash]`): [`src/build_info.rs`](src/build_info.rs), [`build.rs`](build.rs), [`src/cli.rs`](src/cli.rs), [`src/companies_accounts.rs`](src/companies_accounts.rs), [`docs/runbooks/org_account_smoke_test.md`](docs/runbooks/org_account_smoke_test.md). `product_label()` already reads `CARGO_PKG_VERSION` — do not invent a second source of truth. Leave FreeBSD `.pkg` fixture versions (`craft_test_vauban_pkg("0.1.0")`) alone; those are package filenames, not the crate.
- [`Cargo.toml`](Cargo.toml) facade + build-dep `topcoat = "0.8.1"` (keep `tailwind`, `font-fontsource`, `mail`, `mail-smtp`, `multipart`)
- [`Justfile`](Justfile) `topcoat_cli_version := "0.8.1"` then `just ensure-topcoat` **before** `topcoat fmt`
- [`src/app.rs`](src/app.rs) `.trailing_slash(TrailingSlash::Strict)`

Flip pins in the **same** lot or CI stays red:

- [`scripts/check_topcoat_0_8.sh`](scripts/check_topcoat_0_8.sh): CLI / facade `0.8.1`; **require** `TrailingSlash::Strict` in `src/app.rs` and `[package] version = "0.1.2"` (or whatever N+1 is at implement time); keep 0.8 runtime pins (`.runtime()`, `error_boundary`, `signal(cx`, `rust-version = "1.98"`)
- [`tests/integration_tests/topcoat_0_8_invariants_test.rs`](tests/integration_tests/topcoat_0_8_invariants_test.rs): `include_str` pin for `.trailing_slash` + `Strict`

After Lot 1: `just fmt` (CLI 0.8.1) + fmt-check + clippy `-D warnings`.

## Pyramid — extend, do not fork

Reuse `http_edge_*` and `topcoat_0_8_*`. No `topcoat_0_8_1_*` harness.

- **Unit:** [`src/http_canonical.rs`](src/http_canonical.rs) already covers GET/HEAD vs POST and `///`. Keep as-is; add a one-liner that `TrailingSlash` is imported only in `app.rs` if needed.
- **Invariants:** flipped `check_topcoat_0_8.sh` + [`http_edge_invariants_test.rs`](tests/integration_tests/http_edge_invariants_test.rs) still requires `redirect_permanent` + GET/HEAD-only helper. Add `include_str` that `src/app.rs` contains `TrailingSlash::Strict`.
- **Proptest:** keep [`http_edge_proptest.rs`](tests/integration_tests/http_edge_proptest.rs) (`POST` must not use the VCP slash helper). Add / extend a property: arbitrary short POST paths ending in `/` (login, shard-shaped, org docs) do **not** return 308. Keep empty `Option` query (`?q=` / `?page=`) from `topcoat_0_8_proptest` — 0.8.1 does not change that.
- **Battle:** [`http_edge_battle_test.rs`](tests/integration_tests/http_edge_battle_test.rs) parallel GET `/login/` still 308. Add a parallel POST `/login/` + one shard-prefix POST `…/` flood: no 308, no 5xx from missing runtime.
- **E2E (in-process router):**
  - GET `/login/` and `/login/?next=1` still **308** to `/login` ([`http_edge_e2e_test.rs`](tests/integration_tests/http_edge_e2e_test.rs))
  - Tighten POST `/login/` from “not 308” to **404** (or at least not 308 **and** not 200)
  - Existing search-shard POSTs to the **declared** path still 200; a forged `shard_path + "/"` is 404 (one assert on an existing shard e2e fixture — do not invent a second shard harness)
  - Re-run (not rewrite) `topcoat_0_8_*`, `magic_link_*`, `auth_tenant_*`, `portal_shell_*` — a green compile with a red existing e2e is a regression
- **Smoke runbook:** add a short successor line on [`docs/runbooks/topcoat_0_8_smoke_test.md`](docs/runbooks/topcoat_0_8_smoke_test.md) (or a thin [`docs/runbooks/topcoat_0_8_1_smoke_test.md`](docs/runbooks/topcoat_0_8_1_smoke_test.md) linked from it): GET `/login/` 308, POST `/login/` 404, CLI `0.8.1`, runtime script still present. Audience / severity / Pass-Fail.

Commit gate: `just validate`.

**Browser** (after automated green): GET `https://localhost:3000/login/` 308 to `/login`; POST `/login/` does not resubmit; login send + cooldown still works. Desktop only.

## Docs / skills (same PR)

- Thin playbook [`.cursor/skills/topcoat/references/UPGRADE-0.8.1.md`](.cursor/skills/topcoat/references/UPGRADE-0.8.1.md) (status **done** at hand-off): pins, Strict, POST-404 invariant, out-of-scope `./` / `SeeOther` as page error.
- Flip [`.cursor/skills/topcoat/SKILL.md`](.cursor/skills/topcoat/SKILL.md) + [web-stack](.cursor/skills/web-stack/SKILL.md) pin lines to **0.8.1**. Last-studied note → tag `v0.8.1`.
- Do **not** rewrite [UPGRADE-0.8.md](.cursor/skills/topcoat/references/UPGRADE-0.8.md) beyond a one-line “next patch: 0.8.1 (done)”.

## Forbidden

- Landing on default `TrailingSlash::Redirect` without rewriting `http_edge` (that is a product change).
- Deleting `http_canonical` “because Topcoat now has slashes”.
- New `topcoat_0_8_1_*` test tree.
- Declaring done after clippy + one unit test.
- Skipping `just fmt-check` because tests passed.
