-- Drop the case-insensitive uniqueness guard. The lower-casing of
-- existing usernames performed by the `up` migration is data, not schema,
-- and is intentionally NOT reverted: the original (mixed-case) spelling
-- is unrecoverable. Only the index is removed here.
DROP INDEX IF EXISTS idx_users_username_lower;
