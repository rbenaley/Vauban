---
name: UI polish CSS pyramid
overview: Apply Topcoat-compatible Concept CSS polish from the make-interfaces-feel-better review (tabular nums, hit areas, drop page-load fade, button press scale, typography, concentric seg radius, outline rail icons), and extend the existing portal_shell pyramid end-to-end.
todos:
  - id: css-polish
    content: "Apply styles.css polish: tabular-nums, hit areas, drop vb-screen vbIn, btn scale 0.96, antialiased/text-wrap, eph-seg radius 6px"
    status: completed
  - id: icons-outline
    content: Outline ico_home/ico_issues at RAIL_STROKE 1.6; CONTROL_STROKE 1.8 constants + unit tests in icons.rs
    status: completed
  - id: inv-check
    content: Pin polish in check_portal_shell.sh + portal_shell_invariants_test.rs
    status: completed
  - id: prop-battle-e2e
    content: Extend portal_shell proptest, battle, and e2e for polish hooks
    status: completed
  - id: runbook
    content: Add section C UI polish to portal_shell_smoke_test.md
    status: completed
  - id: validate
    content: fmt, clippy, check_portal_shell, just test portal_shell_ (+ icons unit)
    status: completed
isProject: false
---

# UI polish (Concept CSS) + portal_shell pyramid

## Constraints

- Express everything in [`styles.css`](styles.css) + [`src/app/_components/icons.rs`](src/app/_components/icons.rs). No Framer/motion, no second styling system, no first-party JS.
- Prefer extending **portal_shell** (checks, tests, runbook) over a new surface name.
- Keep Concept structure borders; do not replace card/list borders with elevation-only shadows.

## CSS / icon changes ([`styles.css`](styles.css), [`icons.rs`](src/app/_components/icons.rs))

1. **Tabular numbers** — `font-variant-numeric: tabular-nums` on `.vb-ephemeral-countdown` and `.vb-stat-value`.
2. **Hit areas** — `.vb-modal-close` and `.vb-ephemeral-revoke` reach ≥40×40px (padding / `min-width`/`min-height` / inline-flex), without overlapping neighbors.
3. **Motion restraint** — remove `animation: vbIn` from `.vb-screen` only; keep `vbIn` on `.vb-modal` / confirm overlays.
4. **Scale on press** — on `a.vb-btn, button.vb-btn` (not `span.vb-btn`): `transition-property: transform` + `:active { transform: scale(0.96) }`.
5. **Typography** — `-webkit-font-smoothing: antialiased` (+ moz grayscale) on `body`; `text-wrap: balance` on `h1.vb-title`; `text-wrap: pretty` on `.vb-lead` and `.vb-modal-body p`.
6. **Concentric radius** — `.vb-eph-seg` outer radius `6px` (inner btn `4px` + padding `2px`).
7. **Rail icons** — convert `ico_home` and `ico_issues` from fill to stroke outline at `1.6` (same as docs/builds). Introduce named constants `RAIL_STROKE = "1.6"` and `CONTROL_STROKE = "1.8"` in `icons.rs` and use them in SVG attributes so unit tests can pin the split (rail vs controls).

## Pyramid (surface: portal_shell)

| Layer | Deliverable |
|-------|-------------|
| **Unit** | `#[cfg(test)]` in [`icons.rs`](src/app/_components/icons.rs): `RAIL_STROKE` / `CONTROL_STROKE` values; source of `ico_home` / `ico_issues` must contain `stroke=` and not whole-SVG `fill="currentColor"`. |
| **Invariants** | Extend [`scripts/check_portal_shell.sh`](scripts/check_portal_shell.sh) + [`portal_shell_invariants_test.rs`](tests/integration_tests/portal_shell_invariants_test.rs): pin `tabular-nums` on countdown + stat-value; `.vb-screen` must **not** use `vbIn`; `.vb-modal` still uses `vbIn`; `.vb-btn:active` / `scale(0.96)`; modal-close + revoke min 40px; `antialiased`; eph-seg `border-radius: 6px`; rail icons stroke pins via `include_str!` on `icons.rs`. |
| **Proptest** | Extend [`portal_shell_proptest.rs`](tests/integration_tests/portal_shell_proptest.rs): for a fixed table of required CSS substrings (the polish pins), every entry appears in `styles.css` (property over the pin list). |
| **Battle** | Extend [`portal_shell_battle_test.rs`](tests/integration_tests/portal_shell_battle_test.rs): parallel GETs still return OK and bodies keep polish hooks (`vb-screen`, `vb-btn`, and when hitting a docs modal path if already covered — otherwise login + org home + builds list class markers). |
| **E2E** | Extend [`portal_shell_e2e_test.rs`](tests/integration_tests/portal_shell_e2e_test.rs): authenticated org home HTML contains `vb-stat-value`; builds expand / ephemeral path (or list page) exposes `vb-ephemeral-countdown` class when fixture has a link; docs modal HTML contains `vb-modal-close`. No assertion that CSS file content is inlined — class hooks only. |
| **Smoke runbook** | Extend [`docs/runbooks/portal_shell_smoke_test.md`](docs/runbooks/portal_shell_smoke_test.md) with section **C -- UI polish**: countdown digits do not jitter; page nav has no full-screen fade; primary button press feels slight scale; modal close / revoke are easy to click. |

## Validation

```bash
just fmt
just clippy
bash scripts/check_portal_shell.sh
just test portal_shell_
```

(Plus unit filter for `icons::tests` if not covered by `portal_shell_`.)

## Out of scope

- Framer / stagger / client date formatting / replacing Concept borders with shadows.
- Changing login splash brand layout or rail geometry beyond hit-area padding on the listed controls.
