-- Many-to-many: assets <-> asset_groups (replaces assets.group_id).
CREATE TABLE asset_asset_groups (
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    asset_group_id INTEGER NOT NULL REFERENCES asset_groups(id) ON DELETE CASCADE,
    PRIMARY KEY (asset_id, asset_group_id)
);

CREATE INDEX idx_asset_asset_groups_asset_id ON asset_asset_groups(asset_id);
CREATE INDEX idx_asset_asset_groups_asset_group_id ON asset_asset_groups(asset_group_id);

INSERT INTO asset_asset_groups (asset_id, asset_group_id)
SELECT id, group_id FROM assets WHERE group_id IS NOT NULL;

ALTER TABLE assets DROP COLUMN group_id;
