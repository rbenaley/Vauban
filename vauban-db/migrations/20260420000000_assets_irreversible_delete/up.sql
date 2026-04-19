-- Issue #17 (SEC-11 follow-up): make asset deletion semantically
-- irreversible. Soft-delete becomes an audit-only state and the
-- database itself enforces the invariants -- application code can no
-- longer recreate, restore or leak secrets from a deleted asset.
--
-- Companion application changes live in
-- vauban-web/src/handlers/web/assets.rs::create_asset_web
-- (no more reactivation branch; UniqueViolation is the canonical signal
-- that an active triplet already exists) and in
-- vauban-web/src/handlers/web/assets.rs::delete_asset_web (still purges
-- connection_config explicitly as defence-in-depth, even though the
-- CHECK constraint below now also enforces it).

-- Step 1 (PRE-EXISTING — documented here for completeness).
--
-- The partial unique index that enforces I1 (at most one ACTIVE row
-- per (hostname, port, connection_username) triplet, with tombstones
-- excluded so audit history can preserve unbounded prior incarnations)
-- already exists since migration 20260330000000_add_connection_username
-- as `idx_assets_hostname_port_username_active`. We deliberately do
-- NOT recreate it here -- the schema is already correct -- and we
-- attach a comment so future readers can find the contract from this
-- file too.

COMMENT ON INDEX idx_assets_hostname_port_username_active IS
    'Issue #17 (originally introduced in 20260330000000_add_connection_username): '
    'at most one active asset per (hostname, port, username). Tombstones '
    '(is_deleted=true) are deliberately excluded so audit history can preserve '
    'unbounded prior incarnations of the same triplet. Maintained jointly with '
    'handlers::web::assets::create_asset_web (catches UniqueViolation 23505) and '
    'the assets_no_resurrection trigger added below (forbids '
    'is_deleted=true -> false transitions).';

-- Step 2: corrective scrub of any pre-fix tombstone that still carries
-- an encrypted secret envelope. Idempotent on repeated runs and on
-- fresh installs (no rows match). This closes the residual exposure
-- on environments that ran v0.6.6 before the SEC-11 fix landed and
-- MUST run before the CHECK constraint below, otherwise the migration
-- itself would fail on legacy data.
UPDATE assets
SET connection_config = '{}'::jsonb
WHERE is_deleted = true
  AND connection_config <> '{}'::jsonb;

-- Step 3: hard guarantee that a tombstone cannot carry secrets (I3).
-- Any future code path that forgets to scrub will fail at COMMIT
-- time, not in production six months later when an auditor reads
-- the row. The constraint is intentionally narrow: a tombstone may
-- carry every other column unchanged (name, hostname, deleted_at,
-- created_by_id, ...) for audit lineage, but connection_config MUST
-- be the empty JSON object.
ALTER TABLE assets ADD CONSTRAINT assets_tombstone_no_secrets
    CHECK (NOT is_deleted OR connection_config = '{}'::jsonb);

-- Step 4: hard guarantee that no row can ever transition from
-- is_deleted=true back to false (I4). Implements the "delete is
-- irreversible" policy at the DB layer so a compromised handler,
-- a stray UPDATE, or a future bug cannot resurrect a deleted asset.
--
-- The trigger is BEFORE UPDATE so the violation surfaces with the
-- exact OLD/NEW row context, and is gated on a WHEN clause that only
-- fires when the is_deleted column actually transitions, keeping the
-- per-update overhead negligible for the common case (status, name,
-- description edits).
CREATE OR REPLACE FUNCTION assets_no_resurrection() RETURNS trigger AS $$
BEGIN
    IF OLD.is_deleted = true AND NEW.is_deleted = false THEN
        RAISE EXCEPTION 'asset % is soft-deleted and cannot be restored (issue #17 policy: delete is irreversible)', OLD.uuid
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER assets_no_resurrection_trg
    BEFORE UPDATE ON assets
    FOR EACH ROW
    WHEN (OLD.is_deleted IS DISTINCT FROM NEW.is_deleted)
    EXECUTE FUNCTION assets_no_resurrection();

COMMENT ON FUNCTION assets_no_resurrection() IS
    'Issue #17: DB-level enforcement that soft-delete is irreversible. '
    'Bypassing this trigger requires session_replication_role=replica '
    '(superuser only) and is reserved for explicit one-shot data '
    'migrations -- never for application code.';

-- Step 5: read-only convenience view exposing only active rows. The
-- physical `assets` table remains accessible to audit/admin paths and
-- to migrations; new application code that has no business seeing
-- tombstones should target `assets_active` instead, so a forgotten
-- WHERE is_deleted=false can never re-leak a deleted row.
--
-- Existing handlers continue to query `assets` directly; migration to
-- the view is incremental and out of scope for this PR (the CHECK
-- constraint and trigger above already make leakage / resurrection
-- structurally impossible regardless of which name the handler uses).
CREATE VIEW assets_active AS
    SELECT * FROM assets WHERE is_deleted = false;

COMMENT ON VIEW assets_active IS
    'Issue #17: filtered projection of `assets` exposing only rows '
    'where is_deleted = false. Intended as the default target for new '
    'application queries that should never see tombstones. The base '
    'table remains the source of truth (FKs from proxy_sessions etc. '
    'still point at assets.id).';

-- ---------------------------------------------------------------------
-- Future-proofing note (intentionally NOT executed today)
-- ---------------------------------------------------------------------
--
-- If/when any of the following thresholds are crossed, the next
-- structural step is to convert `assets` to a PARTITIONED TABLE
-- partitioned by `is_deleted`:
--
--     CREATE TABLE assets (...) PARTITION BY LIST (is_deleted);
--     CREATE TABLE assets_active_part
--         PARTITION OF assets FOR VALUES IN (false);
--     CREATE TABLE assets_tombstone_part
--         PARTITION OF assets FOR VALUES IN (true);
--
-- Benefits at that scale:
--   * the tombstone partition can live on slower / cheaper tablespace,
--   * a retention policy reduces to DETACH PARTITION + archive-to-S3,
--   * planner statistics on the active partition stay tight, no
--     longer skewed by an ever-growing tombstone tail,
--   * VACUUM / autovacuum pressure on the active set drops sharply.
--
-- Re-evaluate quarterly against these triggers:
--   * SELECT count(*) FROM assets WHERE is_deleted = true;
--     If > 100k OR > 5x the active count, schedule the partitioning.
--   * pg_stat_user_tables.n_dead_tup on `assets` rising faster than
--     autovacuum can keep up (visible as growing n_dead_tup between
--     scheduled vacuum runs).
--   * Any policy change that extends tombstone retention beyond the
--     active-asset retention horizon (separate retention windows are
--     much easier to enforce as separate partitions).
--
-- The partitioning migration is non-trivial -- the FK from
-- proxy_sessions.asset_id needs to point at the parent table, and the
-- existing `connection_username` partial unique index needs to be
-- recreated per-partition. Doing it preemptively today is not
-- justified by current data volumes; this comment is the deliberate
-- reminder so the decision is revisited when the metrics warrant it.
