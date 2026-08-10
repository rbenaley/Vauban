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

1. **Add `issues.version`** (unsigned integer, monotonic) to the Toasty
   model and a Toasty migration. Initialize existing rows to a shared
   baseline (`0` or `1`); new issues start at that baseline.
2. **Every successful lifecycle status transition** goes through one
   advance helper that:
   - loads the row (including `version`);
   - runs `IssueState::transition`;
   - `UPDATE … SET status, version = version + 1, updated_at = … WHERE id
     = … AND version = expected`;
   - treats **zero rows affected** as `PersistError::Conflict`;
   - appends the `status_change` timeline row only after a successful
     CAS.
3. **Optimistic locking is the default.** Pessimistic row locks are not
   required for v1. Revisit only if product adds a high-contention
   claim/assign path.
4. **`updated_at` remains display / sort metadata**, not the CAS token.
5. **Conflict UX:** never report success; refresh detail and signal the
   user (soft query flag or equivalent). Bounded retry is allowed for
   transient identical-event races; after exhaustion, surface Conflict.
6. **v1 scope:** CAS applies to **status transitions** only. Replies and
   attachments do not bump `version` unless a later ADR expands the
   token.
7. **Battle tests are mandatory** before calling the seam done:
   identical concurrent transitions, and divergent `Close` ∥ `Reopen`
   from `Resolved` (exactly one winner; final state in the legal set).

## Consequences

- Implementation must not leave `apply_issue_status` /
  close/reopen helpers on a blind `update()` path once the FSM seam
  ships.
- Toasty CAS syntax is verified at coding time; a local SQL escape
  hatch is acceptable if the ORM cannot express “update where version”
  cleanly, provided it stays inside the advance helper.
- Exports / support debugging SHOULD include `version` when dumping an
  issue row.
- Accepting this ADR without accepting the parent architecture’s
  transition graph is allowed, but coding still waits on architecture
  acceptance (§11 checklist).
