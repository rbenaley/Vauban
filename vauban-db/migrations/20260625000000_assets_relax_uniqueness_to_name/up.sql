-- Relax the asset uniqueness model from the
-- (hostname, port, connection_username) triplet to the asset `name`.
--
-- Rationale: a single physical host legitimately hosts many accounts
-- (root@host, deploy@host, an RDP "break-glass" Administrator, a
-- service account, ...). Worse, two operators may want two *distinct*
-- catalog entries that point at the very same (hostname, port,
-- username) tuple (e.g. one named "prod-db (read replica)" and one
-- named "prod-db (failover drill)"). The old triplet index made that
-- impossible and surfaced as a spurious "asset already exists" error.
--
-- New contract (active rows only):
--   * `name` is UNIQUE among ACTIVE assets (is_deleted = false), so the
--     admin asset catalog stays unambiguous.
--   * (hostname, port, connection_username) is NO LONGER constrained --
--     the same target may be registered any number of times under
--     different names.
--   * Tombstones (is_deleted = true) remain EXCLUDED from the index so
--     audit history keeps an unbounded list of prior incarnations and
--     a deleted name can be reused by a fresh active row (a brand-new
--     UUID -- the `assets_no_resurrection_trg` trigger still forbids
--     flipping is_deleted back to false).
--
-- Independence note: this migration touches ONLY the uniqueness index.
-- The irreversible-delete machinery from
-- 20260420000000_assets_irreversible_delete -- the
-- `assets_tombstone_no_secrets` CHECK and the `assets_no_resurrection_trg`
-- trigger -- does NOT depend on the triplet index and is left untouched.

-- Step 1: defensive de-duplication of any pre-existing ACTIVE rows that
-- already share a name (the old schema never constrained `name`, so
-- duplicates may exist on upgraded installs). The earliest row per
-- name (lowest id) keeps its name; every later collision is suffixed
-- with its globally-unique id so the UNIQUE index below can be built.
-- `left(name, 80)` keeps headroom under the VARCHAR(100) cap for the
-- " #<id>" suffix. Idempotent on fresh installs (no rows match).
UPDATE assets a
SET name = left(a.name, 80) || ' #' || a.id
WHERE a.is_deleted = false
  AND EXISTS (
    SELECT 1
    FROM assets b
    WHERE b.is_deleted = false
      AND b.name = a.name
      AND b.id < a.id
  );

-- Step 2: drop the old triplet partial unique index.
DROP INDEX IF EXISTS idx_assets_hostname_port_username_active;

-- Step 3: enforce the new per-name uniqueness on active rows only.
CREATE UNIQUE INDEX idx_assets_name_active
    ON assets(name)
    WHERE is_deleted = false;

COMMENT ON INDEX idx_assets_name_active IS
    'At most one ACTIVE asset per `name` (is_deleted=false). Replaces the '
    'former (hostname, port, connection_username) triplet index '
    '(idx_assets_hostname_port_username_active, dropped in '
    '20260625000000_assets_relax_uniqueness_to_name) so the same '
    'host/port/account can be registered under several distinct names -- '
    'multiple accounts per host are now first-class. Tombstones are '
    'deliberately excluded so audit history is unbounded and a deleted '
    'name can be reused by a fresh active row. Maintained jointly with '
    'handlers::web::manage_assets::{create_asset_web,update_asset_web} and '
    'handlers::api::manage_assets::{create_asset,update_asset} (all catch '
    'UniqueViolation 23505 and surface "name already exists").';
