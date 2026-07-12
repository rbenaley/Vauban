-- Provenance dimension for organisational vault secret rules.
--
-- A secret access rule becomes a TRIPLE:
--   (user_group_id, secret_group_id, asset_group_id)
--
-- The new asset_group_id (read-only FK to the existing asset_groups
-- table, same status as the vauban_groups subject FK) restricts WHERE
-- the M2M call may come from: the caller's source IP must match an
-- asset that is a member of the rule's asset group (or any known asset
-- when the rule points at the virtual "All assets" singleton), and the
-- matched asset must actively prove its pinned host identity (SSH host
-- key challenge / RDP cert SPKI pin) before the rule can grant.
--
-- Backfill: pre-existing rules carry no provenance restriction, so they
-- are pointed at the virtual "All assets" group (kind='all'), which
-- preserves their semantics under the new invariant "the caller must at
-- least be a known, identity-verified asset".

-- 1. Add the column (nullable first so the backfill can run).
ALTER TABLE secret_access_rules
    ADD COLUMN asset_group_id INTEGER REFERENCES asset_groups(id) ON DELETE CASCADE;

-- 2. Backfill existing rules onto the virtual "All assets" singleton.
--    Fail loud if the singleton is missing: the invariant cannot be
--    installed on a database where the virtual group was never seeded.
DO $$
DECLARE
    virtual_id INTEGER;
BEGIN
    SELECT id INTO virtual_id
        FROM asset_groups
        WHERE kind = 'all';
    IF virtual_id IS NULL THEN
        RAISE EXCEPTION
            'virtual "All assets" group (kind=''all'') not found; cannot backfill secret_access_rules.asset_group_id';
    END IF;

    UPDATE secret_access_rules
        SET asset_group_id = virtual_id
        WHERE asset_group_id IS NULL;
END $$;

-- 3. Lock the column.
ALTER TABLE secret_access_rules
    ALTER COLUMN asset_group_id SET NOT NULL;

-- 4. Uniqueness moves from the couple to the triple.
ALTER TABLE secret_access_rules
    DROP CONSTRAINT secret_access_rules_user_group_id_secret_group_id_key;
ALTER TABLE secret_access_rules
    ADD CONSTRAINT secret_access_rules_user_secret_asset_group_key
    UNIQUE (user_group_id, secret_group_id, asset_group_id);

CREATE INDEX idx_secret_access_rules_asset_group ON secret_access_rules(asset_group_id);
