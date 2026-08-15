-- Drop the CHECK only. Do not reactivate tombstones.
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_tombstone_is_inactive;
