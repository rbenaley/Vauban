-- Revert the provenance triple back to the (user, secret) couple.

DROP INDEX IF EXISTS idx_secret_access_rules_asset_group;

ALTER TABLE secret_access_rules
    DROP CONSTRAINT secret_access_rules_user_secret_asset_group_key;

-- Restoring the couple uniqueness can fail if several rules share the
-- same (user_group, secret_group) with different asset groups; keep the
-- lowest id and drop the rest (the down path is lossy by nature).
DELETE FROM secret_access_rules sar
    USING secret_access_rules keeper
    WHERE keeper.user_group_id = sar.user_group_id
      AND keeper.secret_group_id = sar.secret_group_id
      AND keeper.id < sar.id;

ALTER TABLE secret_access_rules
    ADD CONSTRAINT secret_access_rules_user_group_id_secret_group_id_key
    UNIQUE (user_group_id, secret_group_id);

ALTER TABLE secret_access_rules
    DROP COLUMN asset_group_id;
