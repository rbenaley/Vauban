-- Disable triggers FIRST so the seed row can be removed.
DROP TRIGGER IF EXISTS block_mutation_on_virtual_groups_delete ON asset_groups;
DROP TRIGGER IF EXISTS block_mutation_on_virtual_groups_update ON asset_groups;
DROP TRIGGER IF EXISTS block_membership_on_virtual_groups_update ON asset_asset_groups;
DROP TRIGGER IF EXISTS block_membership_on_virtual_groups_insert ON asset_asset_groups;
DROP FUNCTION IF EXISTS block_mutation_on_virtual_groups();
DROP FUNCTION IF EXISTS block_membership_on_virtual_groups();

DELETE FROM asset_groups WHERE uuid = '00000000-0000-0000-0000-000000000a11';

DROP INDEX IF EXISTS uniq_asset_groups_kind_singleton;
ALTER TABLE asset_groups DROP CONSTRAINT IF EXISTS asset_groups_kind_check;
ALTER TABLE asset_groups DROP COLUMN IF EXISTS kind;
