-- Fold 'ews_connected' rows back into 'waiting_client' before
-- restoring the pre-July-2026 constraint and partial index.

UPDATE proxy_sessions SET status = 'waiting_client' WHERE status = 'ews_connected';

ALTER TABLE proxy_sessions DROP CONSTRAINT IF EXISTS proxy_sessions_status_chk;
ALTER TABLE proxy_sessions ADD CONSTRAINT proxy_sessions_status_chk
    CHECK (status IN ('pending', 'approved', 'rejected', 'revoked', 'expired', 'orphaned', 'connecting', 'active', 'disconnected', 'terminated', 'failed', 'waiting_client', 'tunnel_active'));

DROP INDEX IF EXISTS idx_proxy_sessions_iacs_active;
CREATE INDEX idx_proxy_sessions_iacs_active
    ON proxy_sessions (ews_uuid, status)
    WHERE session_type = 'iacs_tunnel'
      AND status IN ('waiting_client', 'tunnel_active');
