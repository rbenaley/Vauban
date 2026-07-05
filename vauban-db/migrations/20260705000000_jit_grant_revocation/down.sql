-- Revert JIT grant revocation support.
--
-- WARNING: this down migration can FAIL loudly if the relaxed model was
-- used while in effect:
--   * audit rows with decision 'revoke' / 'update_duration' violate the
--     restored two-value CHECK (and the append-only trigger forbids
--     rewriting them) -- that is intended: the audit trail must never be
--     silently truncated. Rolling back is only safe on an installation
--     that never used the new verbs.
--   * grants in status 'revoked' keep their (now orphan) status string;
--     they behave like 'expired' for every consumer (no connect filter
--     matches them).

ALTER TABLE approval_audit_log
    DROP CONSTRAINT approval_audit_log_decision_check;

ALTER TABLE approval_audit_log
    ADD CONSTRAINT approval_audit_log_decision_check
    CHECK (decision IN ('approve', 'reject'));

ALTER TABLE approval_audit_log
    ALTER COLUMN decision TYPE VARCHAR(8);

ALTER TABLE proxy_sessions
    DROP COLUMN revoked_by_id,
    DROP COLUMN revoked_at;
