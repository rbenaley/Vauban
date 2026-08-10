# ADR 006: Optimistic locking for issue status transitions

**Status:** Accepted  
**Date:** 2026-08-10  
**Related:**
[`VCP_Issue_Lifecycle_FSM_Architecture_EN(1.0).md`](../technical/VCP_Issue_Lifecycle_FSM_Architecture_EN(1.0).md)
(D7, §6),
[`.cursor/audits/fsm-ticket-tracker.md`](../../.cursor/audits/fsm-ticket-tracker.md)
(§6 concurrency / invariant I7),
[`src/issue_status.rs`](../../src/issue_status.rs) (today: unconditional
`update` of `status` / `updated_at`)

## Context

A pure in-memory FSM can still corrupt product state if two requests
read the same issue, each compute a legal next state, and both write
(“last write wins”). The critical case is **divergent** concurrent
events from the same state (example: `Close` ∥ `Reopen` while
`Resolved`): without compare-and-swap, both handlers can return success
while only one trajectory should win.

VCP issues are updated over ordinary HTTPS POST forms from org and
admin detail pages. Conflicts on a single ticket are expected to be
**rare**, but correctness still matters for support trust and timeline
integrity.

Alternatives considered:

| Approach | Rejected because |
|----------|------------------|
| Ignore races | Silent lost updates; fails the Close∥Reopen battle test by construction |
| Pessimistic `SELECT … FOR UPDATE` as default | Extra lock duration on a rare path; harder to express uniformly through Toasty for every caller |
| Use `updated_at` as the token | Second-resolution Unix timestamps collide under parallel POSTs |
| Redis / external lock service | Not in the VCP stack; Postgres is already mandatory |

## Decision

1. **Add `issues.version: u64` with Toasty `#[version]`** on the `Issue`
   model, plus a Toasty migration (existing rows backfilled to `1`).
   Toasty manages the counter on create (initial `1`) and on instance
   updates (condition + atomic increment).
2. **Every successful lifecycle status transition** goes through one
   advance helper that:
   - loads the row (so the in-memory `version` is current);
   - runs `IssueState::transition`;
   - performs an **instance** `issue.update()…exec()` (not a
     query-based update) so OCC conditions on the loaded version;
   - maps `Error::is_condition_failed()` to `PersistError::Conflict`;
   - appends the `status_change` timeline row in the **same Toasty
     transaction** as the status update.
3. **Optimistic locking is the default.** Pessimistic row locks are not
   required for v1. Revisit only if product adds a high-contention
   claim/assign path.
4. **`updated_at` remains display / sort metadata**, not the CAS token.
5. **Conflict UX:** never report success; refresh detail and signal the
   user (soft query flag or equivalent). Bounded retry is allowed for
   transient identical-event races; after exhaustion, surface Conflict.
6. **v1 product focus:** conflict handling and battle tests target
   **status transitions**. Other instance updates on `Issue` also bump
   `#[version]` (Toasty default); that is acceptable and strengthens OCC.
7. **Do not introduce `sqlx` (or raw SQL) for this seam.** Use Toasty
   `#[version]` + instance update + transactions.
8. **Battle tests are mandatory** before calling the seam done:
   identical concurrent transitions, and divergent `Close` ∥ `Reopen`
   from `Resolved` (exactly one winner; final state in the legal set).

## Consequences

- Implementation must not leave close/reopen helpers on a blind
  non-OCC `update()` path once the FSM seam ships.
- Design reviews reject adding `sqlx` solely for issue status CAS.
- Exports / support debugging SHOULD include `version` when dumping an
  issue row.
- Accepting this ADR without accepting the parent architecture’s
  transition graph is allowed, but coding still waits on architecture
  acceptance (§11 checklist).
