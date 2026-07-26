---
name: quality-assurance
description: >-
  Testing and validation cycle for VCP. Use after significant code
  changes and before proposing a commit or hand-off.
---

# Quality Assurance

Companion hard gates:

- `.cursor/rules/dev-validation-cycle.mdc`
- `.cursor/rules/vcp-test-pyramid.mdc` (behavioral surfaces)

## 0. Validation cycle (every significant change)

A task is **not done** until format, clippy, relevant structural lints,
and tests all pass on the touched scope.

1. **Format** — `rtk cargo fmt` (+ `topcoat fmt` when macros changed)
2. **Clippy** — warnings as errors on touched crates
3. **Structural lints** — matching `scripts/check_*.sh` only
4. **Focused tests** — change + denial paths; then widen before hand-off

```text
rtk cargo fmt --all -- --check
rtk cargo clippy -p <crate> --all-targets -- -D warnings
# optional: bash scripts/check_<surface>.sh
rtk cargo test -p <crate> -- <filter> -- --test-threads=1
```

### Symmetric process failures

| Failure | Why |
|---------|-----|
| Skip clippy because it compiles | Misses `-D warnings` CI denials |
| Skip tests because clippy is green | Misses behavioral regressions |
| Clippy + a few unit tests, skip pyramid | Misses drift, races, staging gaps |
| Bare `#[allow]` without documented invariant | Prefer refactor / Ctx bundling |
| Fix a failing test and not re-run it | Silent reopen |

## 1. Behavioral test pyramid

Deliver the layers in `vcp-test-pyramid.mdc` by default for significant
behavioral changes: unit, invariants, proptest, battle, E2E, smoke
runbook.

| Layer | Intent |
|-------|--------|
| Unit | Pure domain rules (entitlements, validation, redaction) |
| Invariants | Source / policy shape pins (`check_*.sh`, drift tests) |
| Proptest | Properties over input spaces |
| Battle | Contention / parallel clients |
| E2E | Page + session + DB (or narrow real boundary) |
| Smoke runbook | Staging checklist CI cannot replace |

### Always cover denial paths

For auth, multi-tenant, Casbin, and license / billing surfaces:

- Wrong organization / tenant ID
- Expired or missing session
- Missing Casbin permission
- Missing entitlement
- CSRF / method mismatch where applicable
- Anti-enumeration where existence would leak across tenants (prefer
  404 over chatty 403 when appropriate)

Happy-path-only tests are insufficient for those seams.

### Security checklist (auth / forms / APIs / transport)

- [ ] Injection tests for user-controlled inputs (SQL / query builders)
- [ ] XSS: untrusted strings are escaped by the template pipeline
- [ ] CSRF on cookie-authenticated mutations
- [ ] Rate limiting on login / sensitive endpoints when present
- [ ] Expired session / invalid token denial
- [ ] Authorization: wrong role **and** wrong org
- [ ] No secrets / raw license keys / card data in logs
- [ ] Public edge TLS 1.3-only (staging smoke: protocol / cipher groups)
- [ ] Outbound TLS clients reject invalid certificates
- [ ] No WebSocket routes introduced “for convenience”

## 2. Definition of done

- [ ] `cargo fmt` clean (and `topcoat fmt` if applicable)
- [ ] Clippy `-D warnings` clean on touched crates
- [ ] Relevant structural lints green
- [ ] Focused tests executed and green after the above
- [ ] Pyramid layers required by `vcp-test-pyramid.mdc` present (or
      explicit cosmetic exception)
- [ ] No secrets or customer PII in the repo
- [ ] Docs / plans updated if behavior or public contracts changed

## 3. Stack-specific notes (Topcoat + Toasty)

- Prefer exercising production pages / procedures / shards over a
  parallel “test-only” router.
- Timezone display: assert `vcp_tz` affects HTML without changing
  stored UTC (`timezone-localization.mdc`).
- UI design critique / IA: `designing-beautiful-websites`.
- Implementation conventions: `web-stack`.
- Do **not** import bastion IPC / proxy / recording harnesses.

### Database tests (Toasty + PostgreSQL)

- ORM is **Toasty**; database is **PostgreSQL** (see `web-stack`).
- Integration / E2E tests that touch persistence need a real Postgres
  (CI service, docker compose, or testcontainers) — do not default to
  SQLite for VCP app tests unless a one-off local smoke is explicitly
  documented.
- Provide database URL via TOML (`config/` / `vcp.conf` / CI-mounted
  `VCP_CONFIG_DIR`); never
  commit credentials.
- Tenant and session tests must assert **denial paths** (wrong org,
  expired session hash, missing membership), not only happy-path CRUD.
- Prefer testing through production `db(cx)` / model helpers over a
  parallel Diesel-style harness copied from the bastion.

### Scaffold smoke targets

- `topcoat dev` (or `cargo run`) with Postgres + seed user.
- Login → `/{org}/` dashboard for a member org.
- Wrong org slug → **404** (no cross-tenant leak).
- Non-admin hitting `/{org}/admin/*` → **403** / forbidden.
