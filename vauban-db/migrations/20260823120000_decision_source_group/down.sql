DROP INDEX IF EXISTS idx_proxy_sessions_decision_source_group;
ALTER TABLE proxy_sessions DROP COLUMN IF EXISTS decision_source_group_id;
