-- An access-rule change stores the sentence the client reads
-- ("Session closed because the access rule …"). Machine codes stay short;
-- the sentence names the rule and does not fit in VARCHAR(64).

ALTER TABLE proxy_sessions
  ALTER COLUMN termination_reason TYPE TEXT;

COMMENT ON COLUMN proxy_sessions.termination_reason IS
  'Why the session ended: a machine code, or the sentence shown to the client when an access rule changed';
