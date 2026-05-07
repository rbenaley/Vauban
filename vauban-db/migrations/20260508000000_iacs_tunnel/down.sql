-- Reverse the IACS tunnel scaffolding migration.

-- 7) asset_groups: remove the all_iacs virtual row and shrink the
-- vocabulary. The `block_mutation_on_virtual_groups` trigger refuses
-- DELETEs on non-static rows by design (defense-in-depth), so we
-- temporarily disable it for this single DELETE inside a transaction
-- and re-enable it immediately. Triggers stay enabled for any other
-- DELETE that runs concurrently because Postgres locks
-- `block_mutation_on_virtual_groups_delete` only for THIS table at
-- the row level; no other session is touching `asset_groups` during
-- a `diesel migration redo`.
ALTER TABLE asset_groups DISABLE TRIGGER block_mutation_on_virtual_groups_delete;
DELETE FROM asset_groups
    WHERE uuid = '00000000-0000-0000-0000-000000000a1c'
      AND kind = 'all_iacs';
ALTER TABLE asset_groups ENABLE TRIGGER block_mutation_on_virtual_groups_delete;

ALTER TABLE asset_groups DROP CONSTRAINT IF EXISTS asset_groups_kind_check;
ALTER TABLE asset_groups ADD CONSTRAINT asset_groups_kind_check
    CHECK (kind IN ('static', 'all'));

-- 6) ews_audit_log: revert event vocabulary.
ALTER TABLE ews_audit_log DROP CONSTRAINT IF EXISTS ews_audit_log_event_chk;
ALTER TABLE ews_audit_log ADD CONSTRAINT ews_audit_log_event_check CHECK (event IN (
    'submitted', 'edited', 'cancelled',
    'approved', 'rejected',
    'disabled', 'enabled',
    'offboarded'
));

-- 5) Watchdog index.
DROP INDEX IF EXISTS idx_proxy_sessions_iacs_active;

-- 4) IACS consistency CHECK.
ALTER TABLE proxy_sessions DROP CONSTRAINT IF EXISTS proxy_sessions_iacs_consistency;

-- 3) IACS-specific columns on proxy_sessions.
ALTER TABLE proxy_sessions
    DROP COLUMN IF EXISTS tunnel_target_addr,
    DROP COLUMN IF EXISTS ews_uuid,
    DROP COLUMN IF EXISTS industrial_protocol;

-- 2) Session_type column type.
ALTER TABLE proxy_sessions ALTER COLUMN session_type TYPE VARCHAR(10);

-- 1) Asset type vocabulary. Mirror the up-migration's view dance.
ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_asset_type_chk;
DROP VIEW IF EXISTS assets_active;
ALTER TABLE assets ALTER COLUMN asset_type TYPE VARCHAR(10);
CREATE VIEW assets_active AS
    SELECT * FROM assets WHERE is_deleted = false;
