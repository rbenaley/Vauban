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

1. **Format** — `just fmt` (`cargo fmt` + `topcoat fmt` over all
   `src/**/*.rs`, including `signal` decls)
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
behavioral changes. The classic "70% unit / 25% integration / 5% E2E"
sketch is **insufficient** for auth / tenancy / entitlement seams.
Every significant behavioral change ships **all six layers** unless the
change is explicitly cosmetic (`vcp-test-pyramid.mdc`).

| Layer | Answers | Typical artifact |
|-------|---------|------------------|
| **Unit** | Local happy / sad paths | `#[test]` / `#[tokio::test]` next to the code |
| **Invariants** | Source shape is the contract | `include_str!` / grep pins / `scripts/check_*.sh` |
| **Proptest** | Property over a space of inputs | `proptest!` / random corpora tables |
| **Battle** | Contention / multi-thread / flood | `battle_*` with `Barrier` / parallel load |
| **E2E** | Real product seam already in tree | `*_e2e_test.rs`, page+DB+session path |
| **Smoke runbook** | Staging ops CI cannot replace | `docs/runbooks/*_smoke_test.md` |

Mnemonic:

> unit = *what*, invariants = *how the code must look*, proptest = *for
> all*, battle = *under contention*, E2E = *in the system*, runbook =
> *on staging*.

```
                    ╱╲
                   ╱  ╲     Smoke runbook (staging ops)
                  ╱────╲
                 ╱      ╲   E2E (product seams)
                ╱────────╲
               ╱          ╲ Battle (contention)
              ╱────────────╲
             ╱              ╲ Proptest (properties)
            ╱────────────────╲
           ╱                  ╲ Invariants (source pins)
          ╱────────────────────╲
         ╱                      ╲ Unit (local behavior)
        ╱────────────────────────╲
```

Surface naming (auth / tenant example):
`auth_tenant_{invariants,proptest,battle,e2e}_*` plus unit next to
production code, `scripts/check_auth_tenant.sh`, and
`docs/runbooks/auth_tenant_smoke_test.md`.

### Database for automated tests

- Dedicated Postgres database **`vcp_test`** (user/password `vcp_test`),
  URL in `config/testing.toml`.
- Provision: `just db-create-test` / `scripts/setup_test_db.sh`, or
  automatically via `ensure-vcp-test` when running `just test` /
  `just validate`.
- Schema: Toasty migrations under `toasty/` applied on `db::connect`
  (`vcp-cli migration generate|apply`; not Diesel / not `push_schema`).
- Run tests single-threaded: `just test` / `--test-threads=1`.
- Prefer production `app::router` + model helpers over a parallel
  Diesel/Axum harness from the bastion.

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

- [ ] `just fmt` / `just fmt-check` clean (includes topcoat fmt)
- [ ] Clippy `-D warnings` clean on touched crates
- [ ] Relevant structural lints green
- [ ] Focused tests executed and green after the above
- [ ] Pyramid layers required by `vcp-test-pyramid.mdc` present (or
      explicit cosmetic exception)
- [ ] **List / index pages:** SSR pagination present (`LIST_PAGE_SIZE`,
      `?page=`, chip-row or toolbar pager, filter chips omit `page`);
      pyramid pins helpers + markup + e2e with ≥11 fixtures (see
      `web-stack` § List pagination) — do not ship a bare unpaged list
- [ ] No secrets or customer PII in the repo
- [ ] Docs / plans updated if behavior or public contracts changed

## 3. Stack-specific notes (Topcoat + Toasty)

- Prefer exercising production pages / procedures / shards over a
  parallel “test-only” router.
- Timezone display: assert `vcp_tz` affects HTML without changing
  stored UTC (`timezone-localization.mdc`).
- UI design critique / IA: `designing-beautiful-websites`.
- Implementation conventions: `web-stack`.
- Topcoat progressive UI: enforce the `@click` **function-expression**
  bind contract on SSR HTML (`common/topcoat_click.rs`); do not expect
  CI to drive real clicks — that stays in the smoke runbook. See
  `topcoat` skill §10 + `references/RUNTIME.md`.
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

- `just run` (HTTPS + asset bundle) or `topcoat dev` (HMR) with Postgres + seed user.
- Login → `/{org}/` dashboard for a member org.
- Wrong org slug → **404** (no cross-tenant leak).
- Non-admin hitting `/admin/*` → **404** (anti-enumeration; same as anonymous).
- Capability **entry** denials (`*_read` / compose `*_write`) → **404**;
  visible-resource action denial (`builds_download`) may stay **403**.
