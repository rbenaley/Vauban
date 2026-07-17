-- Input-format constraints for closed-format columns (July 2026).
--
-- Production bug: the slug fields of asset groups and secret groups
-- (and the vault secret name, which is the M2M lookup key) accepted
-- arbitrary strings ("Prod uction {BUG}") because no layer validated
-- the format. This migration is the DB layer of the 4-layer fix
-- (browser pattern -> web handler -> vauban-access re-check -> CHECK):
--
--   1. Normalize existing rows so the constraints can be applied.
--   2. Add named CHECK constraints pinning the canonical grammars.
--
-- Canonical grammars (single source of truth: shared::validation):
--
--   slug / secret name : ^[a-z0-9]([a-z0-9_-]*[a-z0-9])?$
--   hex color          : ^#[0-9a-f]{6}$   (lower-cased)
--   asset status       : online | offline | maintenance | unknown
--
-- System-seeded virtual groups (kind <> 'static', slugs like
-- '__all-assets__') are deliberately exempted from the slug CHECK:
-- their double-underscore prefix marks them as system-managed and
-- they can never be minted through the user-facing handlers.
--
-- users.username / users.email carry NO DB CHECK on purpose: the
-- LDAPS JIT-provisioning path may mint directory identifiers outside
-- the local web charset; the constraint stays applicative (web + API).
--
-- Recovery: re-running this migration is idempotent (normalization
-- UPDATEs are no-ops on already-canonical rows; constraint adds are
-- guarded by DROP CONSTRAINT IF EXISTS).

-- ---------------------------------------------------------------------------
-- 1. Normalize existing asset_groups.slug (static rows only)
-- ---------------------------------------------------------------------------
-- Slugify: lower-case, whitespace runs -> '-', strip anything outside
-- [a-z0-9_-], trim leading/trailing separators, truncate to 90 chars
-- (leaves room for the '-<id>' collision suffix inside VARCHAR(100)).
-- Empty result falls back to 'group-<id>'. Collisions after
-- normalization keep the lowest id on the base slug and suffix the
-- others with '-<id>'; a residual collision (base slug that already
-- ends with another row's suffix) fails the migration loudly rather
-- than silently corrupting data.

WITH normalized AS (
    SELECT id,
           CASE WHEN base = '' THEN 'group-' || id ELSE base END AS candidate
    FROM (
        SELECT id,
               regexp_replace(
                   left(
                       regexp_replace(
                           regexp_replace(lower(slug), '\s+', '-', 'g'),
                           '[^a-z0-9_-]', '', 'g'),
                       90),
                   '^[-_]+|[-_]+$', '', 'g') AS base
        FROM asset_groups
        WHERE kind = 'static'
    ) t
),
dedup AS (
    SELECT id,
           CASE WHEN row_number() OVER (PARTITION BY candidate ORDER BY id) = 1
                THEN candidate
                ELSE candidate || '-' || id
           END AS final_slug
    FROM normalized
)
UPDATE asset_groups g
SET slug = d.final_slug
FROM dedup d
WHERE g.id = d.id
  AND g.slug IS DISTINCT FROM d.final_slug;

-- ---------------------------------------------------------------------------
-- 2. Normalize existing secret_groups.slug (static rows only)
-- ---------------------------------------------------------------------------

WITH normalized AS (
    SELECT id,
           CASE WHEN base = '' THEN 'group-' || id ELSE base END AS candidate
    FROM (
        SELECT id,
               regexp_replace(
                   left(
                       regexp_replace(
                           regexp_replace(lower(slug), '\s+', '-', 'g'),
                           '[^a-z0-9_-]', '', 'g'),
                       90),
                   '^[-_]+|[-_]+$', '', 'g') AS base
        FROM secret_groups
        WHERE kind = 'static'
    ) t
),
dedup AS (
    SELECT id,
           CASE WHEN row_number() OVER (PARTITION BY candidate ORDER BY id) = 1
                THEN candidate
                ELSE candidate || '-' || id
           END AS final_slug
    FROM normalized
)
UPDATE secret_groups g
SET slug = d.final_slug
FROM dedup d
WHERE g.id = d.id
  AND g.slug IS DISTINCT FROM d.final_slug;

-- ---------------------------------------------------------------------------
-- 3. Normalize existing vault_secrets.name (all rows; M2M lookup key)
-- ---------------------------------------------------------------------------

WITH normalized AS (
    SELECT id,
           CASE WHEN base = '' THEN 'secret-' || id ELSE base END AS candidate
    FROM (
        SELECT id,
               regexp_replace(
                   left(
                       regexp_replace(
                           regexp_replace(lower(name), '\s+', '-', 'g'),
                           '[^a-z0-9_-]', '', 'g'),
                       90),
                   '^[-_]+|[-_]+$', '', 'g') AS base
        FROM vault_secrets
    ) t
),
dedup AS (
    SELECT id,
           CASE WHEN row_number() OVER (PARTITION BY candidate ORDER BY id) = 1
                THEN candidate
                ELSE candidate || '-' || id
           END AS final_slug
    FROM normalized
)
UPDATE vault_secrets s
SET name = d.final_slug
FROM dedup d
WHERE s.id = d.id
  AND s.name IS DISTINCT FROM d.final_slug;

-- ---------------------------------------------------------------------------
-- 4. Normalize existing asset_groups.color and assets.status
-- ---------------------------------------------------------------------------

-- Valid but upper-cased colors: canonicalize to lower-case.
UPDATE asset_groups
SET color = lower(color)
WHERE color ~ '^#[0-9A-Fa-f]{6}$'
  AND color <> lower(color);

-- Anything else falls back to the historical column default.
UPDATE asset_groups
SET color = '#6366f1'
WHERE color !~ '^#[0-9a-f]{6}$';

-- Unknown statuses collapse to 'unknown' (the value the display-side
-- parser already reported for them).
UPDATE assets
SET status = 'unknown'
WHERE status NOT IN ('online', 'offline', 'maintenance', 'unknown');

-- ---------------------------------------------------------------------------
-- 5. CHECK constraints
-- ---------------------------------------------------------------------------

ALTER TABLE asset_groups DROP CONSTRAINT IF EXISTS asset_groups_slug_format_chk;
ALTER TABLE asset_groups ADD CONSTRAINT asset_groups_slug_format_chk
    CHECK (kind <> 'static' OR slug ~ '^[a-z0-9]([a-z0-9_-]*[a-z0-9])?$');

ALTER TABLE secret_groups DROP CONSTRAINT IF EXISTS secret_groups_slug_format_chk;
ALTER TABLE secret_groups ADD CONSTRAINT secret_groups_slug_format_chk
    CHECK (kind <> 'static' OR slug ~ '^[a-z0-9]([a-z0-9_-]*[a-z0-9])?$');

ALTER TABLE vault_secrets DROP CONSTRAINT IF EXISTS vault_secrets_name_format_chk;
ALTER TABLE vault_secrets ADD CONSTRAINT vault_secrets_name_format_chk
    CHECK (name ~ '^[a-z0-9]([a-z0-9_-]*[a-z0-9])?$');

ALTER TABLE asset_groups DROP CONSTRAINT IF EXISTS asset_groups_color_chk;
ALTER TABLE asset_groups ADD CONSTRAINT asset_groups_color_chk
    CHECK (color ~ '^#[0-9a-f]{6}$');

ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_status_chk;
ALTER TABLE assets ADD CONSTRAINT assets_status_chk
    CHECK (status IN ('online', 'offline', 'maintenance', 'unknown'));
