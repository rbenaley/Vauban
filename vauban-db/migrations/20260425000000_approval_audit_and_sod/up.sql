-- Approval audit + Separation of Duties (SoD) for the JIT access workflow.
--
-- Two security invariants are pinned at the DB layer (the hard floor of
-- defense-in-depth, non-bypassable even from a raw psql session or a bug in
-- vauban-web / vauban-access):
--
--   1. Separation of duties on `proxy_sessions`: the user who approves (or
--      rejects) a request MUST NOT be the requester. Two CHECK constraints
--      enforce `approved_by_id <> user_id` and `rejected_by_id <> user_id`
--      atomically on every INSERT and UPDATE.
--
--   2. Append-only audit log: every approval/rejection decision spawns one
--      row in `approval_audit_log`. A BEFORE UPDATE OR DELETE trigger raises
--      `EXCEPTION 'approval_audit_log is append-only'` so the trail cannot
--      be rewritten by app bugs nor by a non-superuser DBA.
--
-- Snapshots: the audit row denormalises actor / requester usernames and the
-- asset name at decision time. This guarantees the trail stays meaningful
-- even after a later soft/hard delete of the user or asset (the FKs use
-- ON DELETE SET NULL so the row is preserved).
--
-- Recovery: the runbook docs/runbooks/approval_audit.md describes how to
-- query the trail, export to CSV for compliance, and recover from
-- mono-admin lockout (provisioning a second administrator).

-- 1) Reject-side columns (the approve-side already exists from
--    20260328000000_jit_access_columns).
ALTER TABLE proxy_sessions
    ADD COLUMN rejected_by_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN rejected_at TIMESTAMPTZ,
    ADD COLUMN decision_reason TEXT NULL;

-- 2) Separation of Duties: the approver/rejecter must be a different user
--    than the requester. Both constraints accept NULL on the actor side
--    (no decision yet) but reject any row that would make the actor and
--    the requester the same person.
ALTER TABLE proxy_sessions
    ADD CONSTRAINT approval_separation_of_duties
    CHECK (approved_by_id IS NULL OR approved_by_id <> user_id);

ALTER TABLE proxy_sessions
    ADD CONSTRAINT rejection_separation_of_duties
    CHECK (rejected_by_id IS NULL OR rejected_by_id <> user_id);

-- 3) Append-only audit log. One row per approval decision (approve or
--    reject). Snapshots the actor/requester usernames and asset name so
--    the trail survives later user/asset deletions.
CREATE TABLE approval_audit_log (
    id BIGSERIAL PRIMARY KEY,
    session_uuid UUID NOT NULL,
    decision VARCHAR(8) NOT NULL CHECK (decision IN ('approve', 'reject')),
    actor_user_id INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
    actor_username VARCHAR(150) NOT NULL,
    requester_user_id INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
    requester_username VARCHAR(150) NOT NULL,
    asset_uuid UUID NOT NULL,
    asset_name VARCHAR(200) NOT NULL,
    protocol VARCHAR(10),
    duration_override_seconds INTEGER NULL,
    decision_reason TEXT NULL,
    decision_ip INET NULL,
    decision_user_agent TEXT NULL,
    request_id VARCHAR(64) NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 4) Append-only invariant: any UPDATE or DELETE on this table raises.
--    Insertions are the only legitimate write path. Even DBAs without
--    superuser bypass cannot rewrite the audit history without explicitly
--    DROP'ing the trigger first (a loud, auditable action by itself).
CREATE OR REPLACE FUNCTION block_approval_audit_log_mutation()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION
            'approval_audit_log is append-only (UPDATE on id=% rejected)',
            OLD.id
            USING ERRCODE = 'check_violation';
    ELSIF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION
            'approval_audit_log is append-only (DELETE on id=% rejected)',
            OLD.id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER block_approval_audit_log_update
    BEFORE UPDATE ON approval_audit_log
    FOR EACH ROW EXECUTE FUNCTION block_approval_audit_log_mutation();

CREATE TRIGGER block_approval_audit_log_delete
    BEFORE DELETE ON approval_audit_log
    FOR EACH ROW EXECUTE FUNCTION block_approval_audit_log_mutation();

-- 5) Indexes for the typical query patterns:
--    * by session (the detail page joins audit rows back to a session)
--    * by actor (the /audit/approvals page filters by approver)
--    * by requester (compliance: "who approved my access?")
CREATE INDEX idx_approval_audit_log_session_uuid
    ON approval_audit_log (session_uuid);

CREATE INDEX idx_approval_audit_log_actor
    ON approval_audit_log (actor_user_id, created_at DESC);

CREATE INDEX idx_approval_audit_log_requester
    ON approval_audit_log (requester_user_id, created_at DESC);
