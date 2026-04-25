DROP TRIGGER IF EXISTS block_approval_audit_log_delete ON approval_audit_log;
DROP TRIGGER IF EXISTS block_approval_audit_log_update ON approval_audit_log;
DROP FUNCTION IF EXISTS block_approval_audit_log_mutation();

DROP INDEX IF EXISTS idx_approval_audit_log_requester;
DROP INDEX IF EXISTS idx_approval_audit_log_actor;
DROP INDEX IF EXISTS idx_approval_audit_log_session_uuid;

DROP TABLE IF EXISTS approval_audit_log;

ALTER TABLE proxy_sessions DROP CONSTRAINT IF EXISTS rejection_separation_of_duties;
ALTER TABLE proxy_sessions DROP CONSTRAINT IF EXISTS approval_separation_of_duties;

ALTER TABLE proxy_sessions DROP COLUMN IF EXISTS decision_reason;
ALTER TABLE proxy_sessions DROP COLUMN IF EXISTS rejected_at;
ALTER TABLE proxy_sessions DROP COLUMN IF EXISTS rejected_by_id;
