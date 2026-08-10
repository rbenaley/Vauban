# ADR 005: Issue lifecycle FSM is capability-blind

**Status:** Accepted  
**Date:** 2026-08-10  
**Related:**
[`VCP_Issue_Lifecycle_FSM_Architecture_EN(1.0).md`](../technical/VCP_Issue_Lifecycle_FSM_Architecture_EN(1.0).md)
(D5, §5),
[`.cursor/audits/fsm-ticket-tracker.md`](../../.cursor/audits/fsm-ticket-tracker.md)
(illustrative admin/QA Close guard — **not** adopted),
[`casbin-permissions.mdc`](../../.cursor/rules/casbin-permissions.mdc),
[`src/issue_status.rs`](../../src/issue_status.rs) (shipped close/reopen
gates at the HTTP layer)

## Context

The FSM analysis draft shows optional **guards inside**
`transition(state, event, ctx)` (for example: only `admin` / `qa` may
`Close` from `Resolved`). VCP already authorizes issue mutations with:

1. Casbin-format **`PermissionContext`** (`issues_write` / `issues_read`);
2. **Tenant** membership on `/{org}/…` (or staff nest + `admin_view` /
   staff helpers on `/admin/…`).

Product clarification for the lifecycle redesign: **clients and staff
may both close an issue once it is `Resolved`**, with no extra
lifecycle role. Introducing role strings into the FSM would duplicate
(and drift from) `PermissionContext`, invite bastion-style role
booleans in `view!`, and complicate proptest models with fake roles.

## Decision

1. **`IssueState::transition` takes only `(self, event)`** (plus whatever
   pure inputs are truly lifecycle-local in a future amend). It MUST NOT
   take portal role, staff flags, or `PermissionContext`.
2. **No `TransitionError::Forbidden` in v1.** Illegal edges are only
   `InvalidTransition`. Authorization failures remain HTTP-layer
   denials (`capability_denied`, soft admin redirect, 404 anti-enum).
3. **Who may call which event** is decided in route handlers / page
   policy (architecture §5.1), using `issues_write` and surface rules —
   not inside the FSM match.
4. If a future rule is “only staff may `Resolve`”, implement it as a
   **handler (or new Casbin action) check before** calling the advance
   helper. Do not add `user_role == "admin"` to the FSM. Amending this
   ADR is required before putting capability checks inside `transition`.

## Consequences

- The generic FSM audit’s Close guard examples are explicitly
  **non-normative** for VCP.
- Unit / proptest suites for the FSM stay free of auth fixtures; authZ
  denial paths stay in portal_issues E2E / smoke.
- Design reviews reject “add role to Context for Close” unless this ADR
  is superseded.
- Architecture §4.3 remains the sole normative edge list; UI
  `next_events` may filter further by surface but cannot grant an edge
  the FSM rejects.
