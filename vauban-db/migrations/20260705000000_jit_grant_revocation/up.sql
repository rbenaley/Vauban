-- JIT grant revocation + post-approval duration updates.
--
-- Until now an APPROVED JIT access grant (proxy_sessions.status =
-- 'approved') was immutable until natural expiry: no admin verb could
-- revoke it or change its duration, so an operator could neither cut a
-- contractor's access instantly nor extend/shorten an ongoing grant.
--
-- New contract:
--   * status 'revoked' is a terminal state for a grant, set by the new
--     admin verb (RecordApprovalDecision kind 'revoke'). Connect-time
--     lookups filter on status = 'approved', so a revoked grant blocks
--     NEW sessions instantly; live sessions are cascaded-terminated by
--     the web layer and backstopped by the WS revalidation probe.
--   * `revoked_by_id` / `revoked_at` record who cut the grant and when.
--     Deliberately NO separation-of-duties CHECK on revoked_by_id:
--     REDUCING access is always legitimate, including revoking a grant
--     one approved oneself (unlike approve/reject, which stay fenced by
--     approval_separation_of_duties / rejection_separation_of_duties).
--   * `approval_audit_log.decision` accepts the two new verbs
--     ('revoke', 'update_duration'); the column is widened so
--     'update_duration' (15 chars) fits. The append-only trigger and
--     the existing indexes are untouched.

-- 1) Revoke-side columns on the grant row.
ALTER TABLE proxy_sessions
    ADD COLUMN revoked_by_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN revoked_at TIMESTAMPTZ;

-- 2) Widen the decision column and extend its CHECK to the new verbs.
--    The original constraint was declared inline on the column in
--    20260425000000_approval_audit_and_sod, so it carries the default
--    name approval_audit_log_decision_check.
ALTER TABLE approval_audit_log
    ALTER COLUMN decision TYPE VARCHAR(16);

ALTER TABLE approval_audit_log
    DROP CONSTRAINT approval_audit_log_decision_check;

ALTER TABLE approval_audit_log
    ADD CONSTRAINT approval_audit_log_decision_check
    CHECK (decision IN ('approve', 'reject', 'revoke', 'update_duration'));
