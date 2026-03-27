-- Re-add the FK from assets.group_id to asset_groups(id).
ALTER TABLE assets
    ADD CONSTRAINT assets_group_id_fkey
    FOREIGN KEY (group_id) REFERENCES asset_groups(id) ON DELETE SET NULL;
