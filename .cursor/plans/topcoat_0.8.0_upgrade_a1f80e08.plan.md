---
name: Topcoat 0.8.0 upgrade
overview: Upgrade VCP from Topcoat 0.6.2 to 0.8.0 in four sequential lots (toolchain + lazy View, layouts/error_boundary, signal() rewrite, thin 0.8 exploits). Playbook is written; pin stays 0.6.2 until Lot 1.
todos:
  - id: lot1-pin-view
    content: "Lot 1: rustc 1.98 + topcoat/CLI 0.8.0 + .runtime() + Result<impl View> / Ok(view!); full pyramid"
    status: pending
  - id: lot2-layouts
    content: "Lot 2: slot Slot<'_> + error_boundary on four layouts; flip check_portal_shell + portal_shell pyramid"
    status: pending
  - id: lot3-signals
    content: "Lot 3: signal(cx, init) rewrite (~30 sites) + retarget signal-statement lints; login/Publish/search/builds pyramid"
    status: pending
  - id: lot4-exploit
    content: "Lot 4: href.is_current on rails; confirm empty Option query; no streaming/tracked reads on auth surfaces"
    status: pending
isProject: false
---

# Topcoat 0.6.2 → 0.8.0 upgrade

Follow [`.cursor/skills/topcoat/references/UPGRADE-0.8.md`](../skills/topcoat/references/UPGRADE-0.8.md). Pin today is **0.6.2** ([`Cargo.toml`](../../Cargo.toml), [`Justfile`](../../Justfile) `topcoat_cli_version`). Target **0.8.0** (not 0.7.0 — 0.8 immediately replaces the signal statement and requires `.runtime()`).

There is **no 0.6.3**. Upstream: [v0.7.0](https://github.com/tokio-rs/topcoat/releases/tag/v0.7.0) (2026-09-05) then [v0.8.0](https://github.com/tokio-rs/topcoat/releases/tag/v0.8.0) (2026-09-09). Studied at `/tmp/topcoat-0.8-study` (`149f0de`).

```mermaid
flowchart LR
  lot1[Lot1_pin_and_lazy_View]
  lot2[Lot2_layouts]
  lot3[Lot3_signals]
  lot4[Lot4_exploit]
  lot1 --> lot2 --> lot3 --> lot4
```

**Hard rules:**

- Raise **MSRV to 1.98** in the same lot as the crate pin (Topcoat 0.7+).
- Add **`.runtime()`** before `runtime::script()` or the root layout panics.
- Do not enable `websocket` / `sse` / `datastar`.
- Do not stream cookie / session writes (`live!` after commit panics the jar).
- Server-side signal `.get()` is user input — never an authZ source.
- Keep list pagination on `?page=N` + `href!` (`list-pagination.mdc`).

Each lot ships a full `vcp-test-pyramid.mdc` on the touched seams (login, layouts/404, Publish, search shards, rail).
