-- MCP Phase C: session status `suspended` (docs/specs/vauban-mcp/09-borne-session.md).
-- Reversible pause with Resume/Terminate recourse; holds live resources.
-- Kept in lock-step with `SessionStatus::ALL` and check_status_vocabulary.sh.

ALTER TABLE proxy_sessions DROP CONSTRAINT IF EXISTS proxy_sessions_status_chk;
ALTER TABLE proxy_sessions ADD CONSTRAINT proxy_sessions_status_chk
    CHECK (status IN (
        'pending', 'approved', 'rejected', 'revoked', 'expired', 'orphaned',
        'connecting', 'active', 'suspended', 'disconnected', 'terminated', 'failed',
        'waiting_client', 'ews_connected', 'tunnel_active'
    ));
