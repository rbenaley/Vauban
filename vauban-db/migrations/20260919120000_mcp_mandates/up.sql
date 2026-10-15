-- Mission Seal PDP persist (vauban-access). Session-scoped; WORM lives elsewhere.
CREATE TABLE mcp_mandates (
    session_id   TEXT PRIMARY KEY,
    mandate_id   TEXT NOT NULL,
    state        JSONB NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_mcp_mandates_expires_at ON mcp_mandates (expires_at);

COMMENT ON TABLE mcp_mandates IS
  'Live Mission Seal MandateState (PDP). DELETE on Clear / session end / TTL. No history.';
