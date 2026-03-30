-- Revert: remove connection_username column and restore old constraint.

DROP INDEX IF EXISTS idx_assets_hostname_port_username_active;

ALTER TABLE assets ADD CONSTRAINT assets_hostname_port_key UNIQUE(hostname, port);

ALTER TABLE assets DROP COLUMN IF EXISTS connection_username;
