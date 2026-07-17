-- Revert the input-format CHECK constraints.
--
-- The data normalization performed by up.sql (slugification of
-- asset_groups.slug / secret_groups.slug / vault_secrets.name,
-- lower-casing of asset_groups.color, collapse of unknown
-- assets.status values) is NOT reversible: the pre-normalization
-- values are gone. This mirrors the convention of prior data-shaping
-- migrations -- down.sql restores the schema, not the data.

ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_status_chk;
ALTER TABLE asset_groups DROP CONSTRAINT IF EXISTS asset_groups_color_chk;
ALTER TABLE vault_secrets DROP CONSTRAINT IF EXISTS vault_secrets_name_format_chk;
ALTER TABLE secret_groups DROP CONSTRAINT IF EXISTS secret_groups_slug_format_chk;
ALTER TABLE asset_groups DROP CONSTRAINT IF EXISTS asset_groups_slug_format_chk;
