-- Add connection_username column to assets table.
-- This promotes the username from the connection_config JSONB to a proper column
-- so it can participate in uniqueness constraints.

ALTER TABLE assets
    ADD COLUMN connection_username VARCHAR(100) NOT NULL DEFAULT 'root';

-- Migrate existing usernames from connection_config JSONB
UPDATE assets
SET connection_username = connection_config->>'username'
WHERE connection_config->>'username' IS NOT NULL
  AND connection_config->>'username' != '';

-- Drop the old UNIQUE(hostname, port) constraint
ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_hostname_port_key;

-- Create a partial unique index on (hostname, port, connection_username)
-- that only applies to non-deleted assets. This allows:
--   1. Multiple assets on the same host with different usernames (root@host vs deploy@host)
--   2. Re-creating a deleted asset with the same (hostname, port, username) tuple
CREATE UNIQUE INDEX idx_assets_hostname_port_username_active
    ON assets(hostname, port, connection_username)
    WHERE is_deleted = false;
