-- Add JIT (Just-In-Time) access columns to proxy_sessions.
-- These support the approval workflow and session duration enforcement.

ALTER TABLE proxy_sessions
    ADD COLUMN approved_by_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN approved_at TIMESTAMPTZ,
    ADD COLUMN max_session_duration INTEGER,
    ADD COLUMN expires_at TIMESTAMPTZ;

CREATE INDEX idx_proxy_sessions_status_pending
    ON proxy_sessions(status) WHERE status = 'pending';

CREATE INDEX idx_proxy_sessions_expires_at
    ON proxy_sessions(expires_at) WHERE expires_at IS NOT NULL AND status = 'active';
