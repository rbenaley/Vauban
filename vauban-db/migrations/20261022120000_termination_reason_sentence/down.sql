ALTER TABLE proxy_sessions
  ALTER COLUMN termination_reason TYPE VARCHAR(64)
  USING left(termination_reason, 64);

COMMENT ON COLUMN proxy_sessions.termination_reason IS
  'R0: machine reason for the decision (user_deleted, access_revoked, …)';
