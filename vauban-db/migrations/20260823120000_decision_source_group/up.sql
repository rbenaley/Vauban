-- TRUSTED R1+: remember which group loss triggered (or is likely to trigger)
-- an MCP access cut, so overturn can pre-select restore target.

ALTER TABLE proxy_sessions
  ADD COLUMN decision_source_group_id INTEGER NULL
    REFERENCES vauban_groups(id);

CREATE INDEX idx_proxy_sessions_decision_source_group
  ON proxy_sessions (decision_source_group_id)
  WHERE decision_source_group_id IS NOT NULL;

COMMENT ON COLUMN proxy_sessions.decision_source_group_id IS
  'User group whose removal is associated with this access decision (MCP); used to pre-select overturn restore';
