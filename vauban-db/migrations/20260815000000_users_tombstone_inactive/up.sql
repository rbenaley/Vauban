-- Tombstones cannot stay login-capable. Soft-delete now sets
-- is_active = false in the same UPDATE as is_deleted = true; this
-- CHECK makes the contract structural so a future writer cannot
-- recreate the mailer / session leak (is_deleted=true, is_active=true).
--
-- Backfill first: staging already has suffixed _deleted_* rows that
-- kept is_active = true.

UPDATE users
SET is_active = false
WHERE is_deleted AND is_active;

ALTER TABLE users
    ADD CONSTRAINT users_tombstone_is_inactive
    CHECK (NOT is_deleted OR NOT is_active);

COMMENT ON CONSTRAINT users_tombstone_is_inactive ON users IS
    'A soft-deleted user must be inactive. delete_user_web sets both '
    'flags; deactivate_user then revokes sessions and API keys.';
