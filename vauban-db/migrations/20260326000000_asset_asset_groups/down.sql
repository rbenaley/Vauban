ALTER TABLE assets ADD COLUMN group_id INTEGER REFERENCES asset_groups(id) ON DELETE SET NULL;

UPDATE assets a
SET group_id = sub.asset_group_id
FROM (
    SELECT DISTINCT ON (asset_id) asset_id, asset_group_id
    FROM asset_asset_groups
    ORDER BY asset_id, asset_group_id
) AS sub
WHERE a.id = sub.asset_id;

DROP TABLE asset_asset_groups;
