-- Issue #8: dedupe login sessions and enforce a per-(user, device, IP) invariant.
--
-- Background: each web login inserted a new row in `auth_sessions` without
-- ever invalidating older rows for the same browser/IP combination. As a
-- result, "My Sessions" displayed the same physical device as N independent
-- entries -- one per past login that had not yet hit `expires_at`. This
-- migration cleans up the historical pollution and adds a unique index that
-- makes the duplication structurally impossible going forward, in tandem
-- with the application-level purge performed at login time
-- (vauban-web/src/handlers/auth.rs::purge_sessions_for_device).

-- Step 1: normalise `device_info` so it can take part in a deterministic
-- UNIQUE index. PostgreSQL treats two NULLs as distinct in unique indexes
-- (without NULLS NOT DISTINCT, PG15+), which would let duplicates slip
-- through whenever the User-Agent header was missing.
UPDATE auth_sessions SET device_info = 'Unknown browser' WHERE device_info IS NULL;
ALTER TABLE auth_sessions ALTER COLUMN device_info SET NOT NULL;
ALTER TABLE auth_sessions ALTER COLUMN device_info SET DEFAULT 'Unknown browser';

-- Step 2: dedupe existing rows. For each (user_id, device_info, ip_address)
-- group, keep the row with the most recent `last_activity` (ties broken by
-- the highest `id`) and delete the rest.
DELETE FROM auth_sessions a
USING auth_sessions b
WHERE a.user_id = b.user_id
  AND a.device_info = b.device_info
  AND a.ip_address = b.ip_address
  AND (a.last_activity, a.id) < (b.last_activity, b.id);

-- Step 3: prophylactic purge of long-idle rows so we start from a clean
-- baseline (mirrors what the periodic cleanup task will do from now on).
DELETE FROM auth_sessions
WHERE last_activity < NOW() - INTERVAL '24 hours';

-- Step 4: enforce the invariant -- at most one live session per
-- (user, device, IP). Combined with the application-level DELETE before
-- INSERT (B) and the cleanup task (C), this guarantees the My Sessions
-- view never shows the same device twice.
CREATE UNIQUE INDEX uniq_auth_sessions_per_device
    ON auth_sessions (user_id, device_info, ip_address);

-- Step 5: index supporting the cleanup task's idle-timeout DELETE.
CREATE INDEX idx_auth_sessions_last_activity
    ON auth_sessions (last_activity);

COMMENT ON INDEX uniq_auth_sessions_per_device IS
    'Issue #8: enforce at most one live login session per (user, device, IP). '
    'Maintained by handlers::auth (DELETE before INSERT in a transaction) '
    'and tasks::cleanup (deletes expired and idle sessions).';
