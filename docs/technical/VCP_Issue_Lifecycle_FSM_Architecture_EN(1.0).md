# VCP issue lifecycle — finite-state machine (design & architecture)

**Version:** 1.0  
**Date:** 2026-08-10  
**Status:** design — **accepted** (2026-08-10). Implementation may
proceed from this document and ADRs 005 / 006.  
**Scope:** canonical lifecycle for portal **issues** (org + admin
surfaces): states, events, pure FSM module, persistence with
optimistic concurrency, authorization boundary, Topcoat integration
seams, and the VCP test pyramid.  
**Stack:** Rust, Topcoat (SSR pages / forms; shards/procedures as
needed), Toasty 0.9 + PostgreSQL.  
**Analysis source:**
[`.cursor/audits/fsm-ticket-tracker.md`](../../.cursor/audits/fsm-ticket-tracker.md)
(generic FSM hardening notes; product adaptations below supersede
illustrative role guards in that draft).  
**Related ADRs (accepted):**
[005](../adr/005-issue-fsm-authz-boundary.md) (FSM is capability-blind),
[006](../adr/006-issue-status-optimistic-locking.md) (optimistic
`version` CAS).  
**Shipped baseline today:** string statuses +
[`src/issue_status.rs`](../../src/issue_status.rs) close/reopen helpers
(no FSM module, no `version` column). See §3 for the delta.

---

## 1. Goals and non-goals

### 1.1 Goals

1. One **closed, finite** set of issue statuses and a single pure
   transition function that is the only place legal edges are defined.
2. **Fail closed** on illegal transitions (typed error, never panic).
3. **Authorization outside the FSM**: Casbin-format
   `PermissionContext` + tenant / staff gates stay at the HTTP / page
   boundary ([ADR 005](../adr/005-issue-fsm-authz-boundary.md)).
4. **Atomic status updates** under concurrency via optimistic locking
   ([ADR 006](../adr/006-issue-status-optimistic-locking.md)).
5. UI action affordances derived from (or checked against) the same
   transition function — no parallel “button matrix” as a second source
   of truth.
6. Full VCP behavioral pyramid on the lifecycle seam (unit → smoke).

### 1.2 Non-goals (this version)

- Hierarchical statecharts, orthogonal regions (priority, assignee,
  SLA clocks as FSM states).
- Configurable-per-tenant transition tables (data-driven FSM).
- WebSocket / live collaborative editing of status.
- Moving authZ into the FSM (`user_role`, admin-only Close, etc.).
- Chaos engineering beyond the battle layer already required by the
  pyramid.

---

## 2. Structural decisions

| # | Decision | Rationale |
|---|----------|-----------|
| **D1** | Flat FSM: four states, four events (see §4) | Matches product IA chips; small enough for exhaustive `match` |
| **D2** | Implement as Rust `enum` + exhaustive `match`, not a runtime transition table | Compile-time exhaustiveness; zero runtime lookup cost |
| **D3** | Pure module `src/issue_fsm.rs` (name finalizable at impl) with **no** Topcoat / Toasty / HTTP imports | Isolates proptest / fuzz / unit from the web stack |
| **D4** | `transition(self, event) -> Result<IssueState, TransitionError>` takes `self` **by value** (`Copy` state) | On `Err`, source state is never mutated (invariant I3) |
| **D5** | FSM has **no** role / capability / membership parameters | AuthZ is request-scoped elsewhere; see ADR 005 |
| **D6** | Persist wire labels as today’s strings (`"Open"`, `"In analysis"`, `"Resolved"`, `"Closed"`) via `Display` / `TryFrom<&str>` | Avoids a Toasty enum migration risk; keeps list chips stable |
| **D7** | `Issue.version: u64` with Toasty `#[version]` OCC; status advances use **instance** `update()` | Native CAS; see ADR 006 — no `sqlx` / raw SQL |
| **D8** | Status mutation path: load → authZ → `transition` → CAS update + timeline row in one logical advance helper | Handlers stay thin; no ad-hoc `issue.update().status(...)` outside that helper |
| **D9** | Timeline: keep `IssueComment` `kind = status_change`, `author_role = system` for user-visible dividers | Compatible with seeded / shipped discussion UI |
| **D10** | Reply blocking stays **policy outside FSM**: block when status is `Resolved` **or** `Closed` (today’s `issue_is_closed`) | Orthogonal to which Close/Reopen edges exist |
| **D11** | Prefer existing **POST form** routes for Close/Reopen (and new events) over inventing a second procedure-only API in v1 | Matches CSRF / `OriginLayer` posture already shipped |
| **D12** | Deny Clippy unwrap/expect/panic on the FSM module | Critical path; adversarial inputs must not abort the process |

---

## 3. Current shipped behavior vs target

Today (close/reopen plan + `issue_status.rs`):

| Action | From | To | Notes |
|--------|------|-----|-------|
| Close | `Open`, `In analysis` | `Closed` | No-op if already `Resolved` or `Closed` |
| Reopen | `Resolved`, `Closed` | `Open` | No-op if already open / in analysis |
| Start analysis / Resolve | — | — | **No** first-class mutation; statuses appear via seed / manual DB |

Target (this architecture, §4):

| Event | From | To |
|-------|------|-----|
| `StartAnalysis` | `Open` | `InAnalysis` |
| `Resolve` | `InAnalysis` | `Resolved` |
| `Close` | `Resolved` | `Closed` |
| `Reopen` | `Resolved` | `InAnalysis` |
| `Reopen` | `Closed` | `Open` |

### 3.1 Accepted product deltas (2026-08-10)

Intentional changes relative to today’s helpers — **locked**:

1. **Close only from `Resolved`.** Close from `Open` / `In analysis`
   is `InvalidTransition` (compatibility Option B rejected).
2. **Reopen from `Resolved` → `In analysis`.** Reopen from `Closed`
   still → `Open` (compatibility Option C rejected).
3. **`StartAnalysis` and `Resolve` are first-class mutations** on the
   admin surface in v1; org routes for those events are omitted
   (§5.1).
4. **Optimistic `version`** on every status write through the advance
   helper ([ADR 006](../adr/006-issue-status-optimistic-locking.md)).

### 3.2 Unchanged product rules

- Who may mutate: anyone who already passes **`issues_write`** plus
  org membership (org routes) or staff + `issues_write` (admin nest).
  No new Casbin resource/action for Close alone.
- Client and staff may both **Close** once the FSM allows
  `Resolved → Closed` (no admin/QA-only guard).
- Anti-enumeration: missing / cross-tenant issue → same denial style as
  today’s reply/close handlers (`capability_denied` / soft redirect).
- Idempotent HTTP UX: repeating Close/Reopen when already at the
  terminal side of that action → **303** to detail without a second
  timeline row (map FSM `InvalidTransition` or a dedicated
  “already applied” branch in the advance helper — see §7.3).

---

## 4. Canonical state machine

### 4.1 States (Rust ↔ wire)

| Rust enum | Postgres / UI string |
|-----------|----------------------|
| `Open` | `Open` |
| `InAnalysis` | `In analysis` |
| `Resolved` | `Resolved` |
| `Closed` | `Closed` |

Parsing is case-insensitive on read where today’s helpers already
normalize; writes always use the canonical casing above.

### 4.2 Events

| Event | Typical UI label (US English) | Intended actor |
|-------|-------------------------------|----------------|
| `StartAnalysis` | Start analysis | Staff (admin detail); optional org later |
| `Resolve` | Mark resolved | Staff |
| `Close` | Close issue | Client **or** staff (`issues_write`) |
| `Reopen` | Reopen issue | Client **or** staff (`issues_write`) |

Actor columns are **UX guidance only**. The FSM does not enforce them
(ADR 005). Route handlers may still hide staff-only buttons on the org
surface without inventing FSM roles.

### 4.3 Transition table (normative)

```text
Open        --StartAnalysis--> InAnalysis
InAnalysis  --Resolve-------> Resolved
Resolved    --Close---------> Closed
Resolved    --Reopen--------> InAnalysis
Closed      --Reopen--------> Open
```

All other `(state, event)` pairs → `TransitionError::InvalidTransition`.

There is **no** `TransitionError::Forbidden` variant in v1 (no guards
inside the FSM). If a future product rule needs a guard that is truly
lifecycle-local (not Casbin), amend this document and ADR 005 together.

#### Rejected alternatives (2026-08-10)

| Id | Proposal | Status |
|----|----------|--------|
| **B** | Also allow `Open` / `InAnalysis` `--Close-->` `Closed` | **Rejected** — keep strict pipeline |
| **C** | `Resolved` `--Reopen-->` `Open` (shipped today) | **Rejected** — reopen returns to analysis |

Revisit only via an amend of this section.

### 4.4 Diagram

```text
                    StartAnalysis
           Open ──────────────────► InAnalysis
            ▲                            │
            │ Reopen                     │ Resolve
            │                            ▼
         Closed ◄──────── Close ──── Resolved
            ▲                            │
            └──────────── Reopen ────────┘
                      (to InAnalysis)
```

### 4.5 Illustrative pure API (normative shape)

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IssueState { Open, InAnalysis, Resolved, Closed }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IssueEvent { StartAnalysis, Resolve, Close, Reopen }

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransitionError {
    InvalidTransition { from: IssueState, event: IssueEvent },
}

impl IssueState {
    pub fn transition(self, event: IssueEvent) -> Result<IssueState, TransitionError> {
        use IssueEvent::*;
        use IssueState::*;
        match (self, event) {
            (Open, StartAnalysis) => Ok(InAnalysis),
            (InAnalysis, Resolve) => Ok(Resolved),
            (Resolved, Close) => Ok(Closed),
            (Resolved, Reopen) => Ok(InAnalysis),
            (Closed, Reopen) => Ok(Open),
            _ => Err(TransitionError::InvalidTransition { from: self, event }),
        }
    }
}
```

`next_events(state)` for UI listing MUST be derived by testing each
`IssueEvent` against `transition` (with `EnumIter` or an explicit
array), not a hand-maintained parallel table.

---

## 5. Authorization boundary

Normative detail: [ADR 005](../adr/005-issue-fsm-authz-boundary.md).

Summary:

1. HTTP handler / page: session → `require_org` or `require_staff` →
   `PermissionContext` (`issues_write` for mutations; `issues_read` for
   views) → load issue in tenant scope.
2. Only then call the advance helper → FSM → CAS.
3. Never pass `portal_role`, `is_staff`, or raw role strings into
   `transition`.
4. UI may hide staff-oriented events on the client surface; forged POST
   of a staff-oriented event from a client who still has `issues_write`
   is accepted by the FSM **if the edge exists**. If product later needs
   “only staff may Resolve”, that is a **handler-level** check (or a new
   Casbin action), not an FSM role guard — document it as an amend.

### 5.1 Handler policy for events (v1) — accepted

| Event | Org `/{org}/issues/...` | Admin `/admin/issues/...` |
|-------|-------------------------|---------------------------|
| `Close`, `Reopen` | `issues_write` + member | staff + `issues_write` |
| `StartAnalysis`, `Resolve` | **omit routes in v1** (404 / no form) | staff + `issues_write` |

Client IA keeps Close/Reopen only; staff drives Open → In analysis →
Resolved. Amend this table if clients must Resolve themselves.

---

## 6. Persistence and optimistic concurrency

Normative detail: [ADR 006](../adr/006-issue-status-optimistic-locking.md).

### 6.1 Schema

Add column on `issues` via Toasty model + migration:

| Column | Type | Notes |
|--------|------|-------|
| `version` | `u64` / `BIGINT` with `#[version]` | Toasty OCC token; create defaults to `1` |

`updated_at` remains the wall-clock stamp for lists/UI; it is **not**
the concurrency token.

### 6.2 Advance helper (logical contract)

```text
advance_issue(db, issue, event) -> Result<AdvanceOutcome, PersistError>

PersistError:
  - Fsm(TransitionError)      // illegal edge
  - Conflict                  // Toasty condition_failed (OCC)
  - UnknownStatus(...)
  - Db(...)
```

Algorithm:

1. Parse `issue.status` → `IssueState` (row already loaded for OCC).
2. `new_state = state.transition(event)?` (or HTTP no-op mapping).
3. Begin a Toasty **transaction**.
4. **Instance** `issue.update().status(…).updated_at(…).exec(&mut tx)` —
   Toasty conditions on the loaded `#[version]` and increments it.
5. On `Error::is_condition_failed()` → `Conflict` (rollback).
6. Insert `status_change` timeline row on the same `tx`; `commit`.

Do **not** use query-based `Issue::filter(…).update()` for this path
(it increments version but does not condition on the loaded snapshot).
Do **not** introduce `sqlx` or hand-written SQL for CAS (ADR 006).

### 6.3 Conflict UX

- Do **not** treat `Conflict` as success.
- Prefer 303 back to detail with a soft flash / query flag
  (e.g. `?err=conflict`) and refreshed status, consistent with other
  soft denial patterns on admin issues.
- Bounded retry (e.g. 2–3 attempts) is allowed inside the helper or
  handler for identical idempotent events; divergent concurrent events
  must surface conflict after retries exhaust.

### 6.4 What bumps `version`

- **Yes:** every successful FSM status transition (instance update).
- Other instance updates on `Issue` (e.g. reply touching `updated_at`)
  also bump `#[version]` under Toasty’s default OCC rules — acceptable
  and strengthens conflict detection.

---

## 7. Integration with Topcoat surfaces

### 7.1 Routes (target)

Keep REST-ish POST forms (CSRF via `OriginLayer`):

| Surface | Examples |
|---------|----------|
| Org | `POST /{org}/issues/{key}/close`, `.../reopen` |
| Admin | `POST /admin/issues/{key}/close`, `.../reopen`, plus `.../start-analysis`, `.../resolve` |
| Reserved | Existing `/vauban/issues/...` aliases → admin targets |

All of the above call the shared advance helper after authZ.

### 7.2 UI derivation

- Detail pages compute allowed events via `next_events(state)` filtered
  by surface policy (§5.1).
- Buttons are SSR forms; no client-only status store.
- Closing/reopening still anchors `#issue-reply` as today.

### 7.3 Idempotence mapping

| Situation | HTTP result | Timeline |
|-----------|-------------|----------|
| Legal transition, CAS ok | 303 detail | One new `status_change` row |
| Illegal transition that means “already there” for Close/Reopen UX | 303 detail | No new row |
| Illegal transition that is a true misuse (e.g. Resolve from Open) | 303 or soft error | No new row; optional flash |
| CAS conflict | 303 + conflict signal | No new row |

Define “already there” explicitly in code comments next to the helper
(e.g. Close while `Closed` → no-op success for HTTP). Do not encode
that as `Ok` inside `transition` — keep the FSM strict; map at the
persist/HTTP layer.

### 7.4 Procedures / shards

v1 does **not** require a `#[procedure]` for status. If a later live
shard needs it, the procedure must call the same advance helper and
must not bypass CAS. Re-check Topcoat 0.5 shard invalidation docs if
that path is added.

---

## 8. Timeline and copy — accepted

| Transition | Timeline body (US English) |
|------------|----------------------------|
| → `InAnalysis` via StartAnalysis | `Moved to analysis` (matches seed phrasing) |
| → `Resolved` via Resolve | `Resolved` |
| → `Closed` via Close | `Closed` |
| → `Open` or `InAnalysis` via Reopen | `Reopened` |

System author fields unchanged (`author_user_id = 0`,
`author_role = system`, `kind = status_change`). Pin these strings in
unit / E2E tests.

---

## 9. Module layout (implementation sketch)

```text
src/issue_fsm.rs          # states, events, transition, next_events, wire parse
src/issue_status.rs       # advance helper, timeline, reply-block helper
                          # (evolves from today’s close/reopen wrappers)
src/models/mod.rs         # Issue.version field + ISSUE_STATUS_* constants
toasty/migrations/00xx_issue_version.sql
src/app/org/issues/…      # authZ + POST forms
src/app/admin/issues/…    # authZ + POST forms (+ start-analysis / resolve)
```

Forbidden: status string literals sprinkled in handlers for mutation
targets — go through `IssueState` / constants.

---

## 10. Invariants and test pyramid

Aligned with
[`.cursor/rules/vcp-test-pyramid.mdc`](../../.cursor/rules/vcp-test-pyramid.mdc)
and the analysis invariants I1–I7 in
`fsm-ticket-tracker.md` (adapted: drop role-guard invariant I6 as
written; replace with authZ-boundary tests outside the FSM).

| Layer | Deliverable |
|-------|-------------|
| **Unit** | Every legal edge; representative illegal edges; wire parse round-trip; `issue_is_closed` / reply-block matrix |
| **Invariants** | Source pins: FSM module isolation; no role param on `transition`; CAS `version` in advance helper; route greps for new POSTs; `scripts/check_portal_issues.sh` extended |
| **Proptest** | Independent reference model == `transition`; random event sequences never panic; status strings stay in the closed catalog |
| **Battle** | Concurrent identical Close; **divergent** Close ∥ Reopen from `Resolved` → exactly one CAS winner; final state ∈ {`Closed`, `InAnalysis`} |
| **E2E** | Staff pipeline Open→…→Closed; client Close from Resolved; client cannot Resolve if routes omitted; wrong-org / anonymous denials; conflict soft UX if exposed |
| **Smoke** | Extend [`portal_issues_smoke_test.md`](../runbooks/portal_issues_smoke_test.md) with Start analysis / Resolve (staff) and Resolved→Closed (client + staff) |

`proptest-state-machine` and `cargo fuzz` are **optional stretch** after
the mandatory pyramid is green; not blockers for v1 acceptance of this
design.

---

## 11. Acceptance checklist

- [x] §4.3 graph accepted (**1A**: Close only from `Resolved`; **2A**:
  Reopen `Resolved` → `In analysis`; Options B/C rejected).
- [x] ADR 005 accepted (FSM capability-blind).
- [x] ADR 006 accepted (optimistic `version` CAS).
- [x] §5.1 surface policy accepted (**3A**: StartAnalysis / Resolve
  admin-only in v1).
- [x] Timeline copy strings frozen (§8).
- [x] Implementation plan (Cursor plan) references this document as SoT
  (`.cursor/plans/issue_lifecycle_fsm_02ac8ded.plan.md`).

---

## 12. Out of scope / future

- Per-tenant custom workflows.
- Assignee / SLA as FSM states.
- Expanding CAS to non-status issue updates.
- C2-style out-of-band confirmation for destructive issue deletes
  (issue delete is not part of this lifecycle).
- Importing bastion ticket machines or Casbin resource names.

---

## 13. Document history

| Ver | Date | Notes |
|-----|------|-------|
| 1.0 | 2026-08-10 | Initial design from FSM audit + product clarifications (no FSM role guards; optimistic locking; strict pipeline Close) |
| 1.0 | 2026-08-10 | **Accepted**: product votes 1A / 2A / 3A; ADRs 005–006 Accepted; Options B/C rejected |
