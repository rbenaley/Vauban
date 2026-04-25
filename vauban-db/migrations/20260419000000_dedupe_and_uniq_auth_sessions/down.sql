-- Reverse of 20260419000000_dedupe_and_uniq_auth_sessions/up.sql.
DROP INDEX IF EXISTS idx_auth_sessions_last_activity;
DROP INDEX IF EXISTS uniq_auth_sessions_per_device;
ALTER TABLE auth_sessions ALTER COLUMN device_info DROP DEFAULT;
ALTER TABLE auth_sessions ALTER COLUMN device_info DROP NOT NULL;
