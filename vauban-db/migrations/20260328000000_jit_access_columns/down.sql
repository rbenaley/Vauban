DROP INDEX IF EXISTS idx_proxy_sessions_expires_at;
DROP INDEX IF EXISTS idx_proxy_sessions_status_pending;

ALTER TABLE proxy_sessions
    DROP COLUMN IF EXISTS expires_at,
    DROP COLUMN IF EXISTS max_session_duration,
    DROP COLUMN IF EXISTS approved_at,
    DROP COLUMN IF EXISTS approved_by_id;
