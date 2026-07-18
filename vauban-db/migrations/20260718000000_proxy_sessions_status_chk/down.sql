-- The 'completed' / 'consumed' -> 'disconnected' normalization is not
-- reversible (the original value is gone); only the constraint is
-- dropped.

ALTER TABLE proxy_sessions DROP CONSTRAINT IF EXISTS proxy_sessions_status_chk;
