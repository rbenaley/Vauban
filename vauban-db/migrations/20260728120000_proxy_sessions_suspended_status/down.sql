-- Fold suspended MCP sessions back to active before dropping the status.
UPDATE proxy_sessions SET status = 'active' WHERE status = 'suspended';

ALTER TABLE proxy_sessions DROP CONSTRAINT IF EXISTS proxy_sessions_status_chk;
ALTER TABLE proxy_sessions ADD CONSTRAINT proxy_sessions_status_chk
    CHECK (status IN (
        'pending', 'approved', 'rejected', 'revoked', 'expired', 'orphaned',
        'connecting', 'active', 'disconnected', 'terminated', 'failed',
        'waiting_client', 'ews_connected', 'tunnel_active'
    ));
