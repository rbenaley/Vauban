-- IACS intermediate lifecycle status 'ews_connected' (July 2026).
--
-- The EWS SSH handshake succeeding is an authenticated presence on the
-- bastion even before the first direct-tcpip channel opens. Without an
-- intermediate status the session stays invisible in Active Sessions
-- (no terminate surface) and leaves no audit anchor. New lifecycle:
--   waiting_client -> ews_connected -> tunnel_active -> terminated/expired
--
-- Kept in lock-step with `SessionStatus::ALL`
-- (vauban-web/src/models/session.rs) and check_status_vocabulary.sh by
-- tests/web/status_vocab_drift_test.rs.

ALTER TABLE proxy_sessions DROP CONSTRAINT IF EXISTS proxy_sessions_status_chk;
ALTER TABLE proxy_sessions ADD CONSTRAINT proxy_sessions_status_chk
    CHECK (status IN ('pending', 'approved', 'rejected', 'revoked', 'expired', 'orphaned', 'connecting', 'active', 'disconnected', 'terminated', 'failed', 'waiting_client', 'ews_connected', 'tunnel_active'));

-- Watchdog partial index: include the new live status.
DROP INDEX IF EXISTS idx_proxy_sessions_iacs_active;
CREATE INDEX idx_proxy_sessions_iacs_active
    ON proxy_sessions (ews_uuid, status)
    WHERE session_type = 'iacs_tunnel'
      AND status IN ('waiting_client', 'ews_connected', 'tunnel_active');
