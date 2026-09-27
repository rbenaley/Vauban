-- R0 TRUSTED: stable access-decision id on MCP (and reusable) session cuts.
-- decision_id is the addressable dossier number (WORM + session UI).
-- termination_reason / decision_actor / decision_at explain who/what/when.
-- Distinct from JIT decision_reason (approve/reject text).

ALTER TABLE proxy_sessions
  ADD COLUMN decision_id VARCHAR(64) NULL,
  ADD COLUMN termination_reason VARCHAR(64) NULL,
  ADD COLUMN decision_actor VARCHAR(128) NULL,
  ADD COLUMN decision_at TIMESTAMPTZ NULL;

CREATE INDEX idx_proxy_sessions_decision_id
  ON proxy_sessions (decision_id)
  WHERE decision_id IS NOT NULL;

COMMENT ON COLUMN proxy_sessions.decision_id IS
  'R0: stable access-decision id (e.g. D-<uuid>) for terminate/restrict; WORM + UI';
COMMENT ON COLUMN proxy_sessions.termination_reason IS
  'R0: machine reason for the decision (user_deleted, access_revoked, …)';
COMMENT ON COLUMN proxy_sessions.decision_actor IS
  'R0: who decided (system:mcp_recheck, system:terminate_live_session, user:<uuid>)';
COMMENT ON COLUMN proxy_sessions.decision_at IS
  'R0: when the decision was recorded';
