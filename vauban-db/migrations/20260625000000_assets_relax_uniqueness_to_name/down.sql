-- Revert to the (hostname, port, connection_username) triplet uniqueness.
--
-- WARNING: this down migration can FAIL if, while the name-based model
-- was in effect, two or more ACTIVE assets were created on the same
-- (hostname, port, connection_username) tuple -- which is exactly what
-- the up migration set out to allow. Recreating the triplet partial
-- unique index will then raise a unique_violation (23505). That is the
-- intended, loud behaviour: rolling back is only safe once the
-- operator has manually reconciled (renamed/deleted) the duplicate
-- triplets. There is no lossless automatic down path.

DROP INDEX IF EXISTS idx_assets_name_active;

CREATE UNIQUE INDEX idx_assets_hostname_port_username_active
    ON assets(hostname, port, connection_username)
    WHERE is_deleted = false;
