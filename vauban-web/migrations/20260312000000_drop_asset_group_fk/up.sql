-- Drop FK from assets.group_id to asset_groups(id).
-- The asset_groups table is now managed by vauban-access and may reside
-- in a separate PostgreSQL instance.  The column is kept for lookups but
-- referential integrity is enforced at the application/IPC level.

ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_group_id_fkey;
