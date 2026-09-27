DROP INDEX IF EXISTS idx_proxy_sessions_decision_id;
ALTER TABLE proxy_sessions
  DROP COLUMN IF EXISTS decision_at,
  DROP COLUMN IF EXISTS decision_actor,
  DROP COLUMN IF EXISTS termination_reason,
  DROP COLUMN IF EXISTS decision_id;
