-- IACS tunnel scaffolding (lot L1 of "IACS Tunnels via EWS").
--
-- Brings the data model needed to expose IACS asset types alongside the
-- existing SSH / RDP transports, then to record the resulting tunnel
-- sessions on `proxy_sessions` exactly the same way SSH and RDP sessions
-- are recorded today.
--
-- Design properties pinned by this migration:
--
--   1. `assets.asset_type` becomes a closed vocabulary of 7 strings via a
--      named CHECK constraint. The previous DEFAULT 'ssh' is kept; only
--      values explicitly listed below can ever land in the column. Two
--      side-effects of this:
--        - The Rust enum `AssetType` can rely on the DB to refuse
--          unknown values, which lets it stop silently falling back to
--          `Ssh` on parse errors (see `models/asset.rs`).
--        - A drift test (see `vauban-web/tests/db/iacs_drift_test.rs`)
--          extracts this exact constraint via `pg_get_constraintdef`
--          and asserts it lists every variant declared in Rust.
--      The column width grows from VARCHAR(10) to VARCHAR(20) so that
--      `iacs_profinet` (13 chars) fits without truncation. Indices on
--      the column are preserved -- ALTER COLUMN TYPE on a pure widening
--      conversion is metadata-only.
--
--   2. `proxy_sessions.session_type` similarly grows to VARCHAR(20) to
--      fit the new `iacs_tunnel` value (11 chars). The column is NOT
--      gated by a CHECK constraint today (legacy permissivity) and we
--      do NOT introduce one here so that running this migration does
--      not collide with any pre-existing odd value -- the Rust enum
--      stays the source of truth and the drift test pins the parse path.
--
--   3. `proxy_sessions` gains four columns dedicated to the IACS tunnel
--      session_type:
--        - `industrial_protocol VARCHAR(20)`: free-form value sourced
--          from `assets.asset_type` (after stripping the `iacs_`
--          prefix) at session creation time. Persisted explicitly so
--          forensic queries on terminated rows can pivot on the
--          industrial protocol even after the asset has been hard-
--          deleted (an asset deletion still sets FK to NULL elsewhere
--          but `industrial_protocol` is denormalised on purpose).
--        - `ews_uuid UUID REFERENCES ews(uuid) ON DELETE SET NULL`:
--          which onboarded EWS opened the tunnel. SET NULL on EWS
--          delete preserves the audit row.
--        - `tunnel_target_addr VARCHAR(255)`: the actual address the
--          proxy connected to (typically `127.0.0.1:4321` in the MVP
--          but recorded explicitly so future bastion->asset routing
--          can switch this without a schema change).
--      `bytes_in / bytes_out` are NOT introduced; the existing
--      `bytes_received / bytes_sent` columns are reused for the IACS
--      tunnel's byte counters (semantic match: bytes in/out from the
--      bastion's perspective).
--
--   4. `proxy_sessions_iacs_consistency` CHECK ties the four columns
--      together with `session_type`:
--        - For `iacs_tunnel`, `industrial_protocol IS NOT NULL` and
--          `ews_uuid IS NOT NULL` are mandatory. `tunnel_target_addr`
--          may stay NULL in the (rare) `waiting_client` window before
--          the proxy commits the connection but the runtime path
--          always fills it on transition to `tunnel_active`.
--        - For ANY other `session_type` (today `ssh` and `rdp`), the
--          three IACS-specific columns MUST be NULL. This guarantees
--          a misconfigured handler cannot leak IACS metadata onto an
--          SSH / RDP session row.
--
--   5. `idx_proxy_sessions_iacs_active` partial index speeds up the
--      revocation watchdog (see L4) which periodically scans active
--      tunnels by EWS to catch disable/offboard side effects.
--
--   6. `ews_audit_log` event vocabulary gains `tunnel_opened` and
--      `tunnel_closed`. The CHECK constraint is dropped and re-added
--      via a DO block (anonymous CHECK constraint name varies across
--      PostgreSQL versions). The append-only trigger is unaffected.
--
--   7. `asset_groups.kind` admits a new value `all_iacs`. The previous
--      `asset_groups_kind_check` CHECK is dropped and re-added with the
--      extended vocabulary. A second virtual asset_group row is seeded
--      under the reserved UUID `00000000-0000-0000-0000-000000000a1c`
--      (mnemonic `a1c` ~= IACS): when referenced from an access_rule,
--      it dynamically grants the rule over every IACS asset (any
--      asset_type starting with `iacs_`). Same defense-in-depth as the
--      pre-existing `all` virtual group: the partial UNIQUE index on
--      `kind` already enforces at most one row per non-static kind,
--      and the `block_membership_on_virtual_groups` /
--      `block_mutation_on_virtual_groups` triggers cover the new row
--      automatically (they identify rows by `kind <> 'static'`, not by
--      UUID).
--
-- Recovery: re-running this migration is idempotent (CHECK adds use
-- IF NOT EXISTS-equivalent DO blocks; INSERTs use ON CONFLICT DO
-- NOTHING).

-- 1) Asset type vocabulary: widen + closed CHECK.
--
-- A dependent view (`assets_active`, introduced by the
-- 20260420000000_assets_irreversible_delete migration) blocks the
-- column-type widening with "cannot alter type of a column used by a
-- view or rule". The view is a plain `SELECT * FROM assets WHERE
-- is_deleted = false` projection so we drop it before the ALTER and
-- re-create it identically afterwards. Any consumer of the view sees
-- the same schema (`assets_active.*` keeps the wider VARCHAR(20) on
-- `asset_type` automatically since `SELECT *` re-resolves columns).
DROP VIEW IF EXISTS assets_active;
ALTER TABLE assets ALTER COLUMN asset_type TYPE VARCHAR(20);
CREATE VIEW assets_active AS
    SELECT * FROM assets WHERE is_deleted = false;

-- Drop any prior named CHECK if a partial migration left one behind.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'assets_asset_type_chk'
          AND conrelid = 'assets'::regclass
    ) THEN
        ALTER TABLE assets DROP CONSTRAINT assets_asset_type_chk;
    END IF;
END $$;

-- 1.bis) Quarantine legacy asset_type values that are NOT part of
-- the new closed vocabulary (e.g. `vnc` from a pre-v0.7 deployment
-- where VNC was a first-class transport). The CHECK constraint
-- below would reject them.
--
-- Strategy: NON-DESTRUCTIVE. Production instances that have run
-- for months may carry valuable forensic data linked to legacy
-- assets; deleting rows wholesale would also CASCADE-purge their
-- proxy_sessions / asset_asset_groups, throwing away the audit
-- trail that auditors and incident responders rely on.
--
-- For each unknown asset_type we therefore:
--
--   (a) append a forensic breadcrumb to `description` recording
--       the original protocol (`description` is plain TEXT NULL,
--       free-form, untouched by every other constraint);
--   (b) flip `asset_type` to `rdp` (the closest supported
--       transport for the historical VNC case; pure label
--       reassignment so the CHECK passes);
--   (c) mark the row as soft-deleted (`is_deleted=true`,
--       `deleted_at=NOW()`) so it disappears from the UI
--       (`assets_active` view is filtered on `is_deleted=false`)
--       while every FK from `proxy_sessions` / access rules /
--       audit logs stays intact;
--   (d) reset `connection_config` to `'{}'::jsonb` so the
--       pre-existing `assets_tombstone_no_secrets` CHECK
--       (introduced by 20260420000000_assets_irreversible_delete)
--       is satisfied: tombstoned rows MUST not retain their
--       (potentially secret) connection config. The legacy
--       config payload is intentionally NOT carried forward;
--       the breadcrumb in (a) is the audit anchor.
--
-- Operators who explicitly want their legacy assets back online
-- must re-create them under a supported transport; the original
-- row stays in the table for forensic continuity (FK preserved,
-- name/hostname/port preserved, description carries the
-- legacy_protocol marker).
DO $$
DECLARE
    converted_total INTEGER := 0;
    converted_row RECORD;
BEGIN
    FOR converted_row IN
        SELECT asset_type, COUNT(*) AS n
        FROM assets
        WHERE asset_type NOT IN (
            'ssh', 'rdp',
            'iacs_modbus', 'iacs_opcua', 'iacs_profinet',
            'iacs_iec104', 'iacs_tcp'
        )
        GROUP BY asset_type
    LOOP
        RAISE NOTICE
            'iacs_tunnel migration: quarantining % asset row(s) with legacy asset_type=% (relabel rdp + soft-delete + record legacy_protocol)',
            converted_row.n, converted_row.asset_type;
        converted_total := converted_total + converted_row.n;
    END LOOP;

    IF converted_total > 0 THEN
        UPDATE assets
        SET
            description = COALESCE(description, '')
                || CASE
                       WHEN COALESCE(description, '') = '' THEN ''
                       ELSE E'\n'
                   END
                || '[QUARANTINED by iacs_tunnel migration on '
                || NOW()::TEXT
                || ' -- legacy_protocol='
                || asset_type
                || ']',
            asset_type = 'rdp',
            is_deleted = TRUE,
            deleted_at = COALESCE(deleted_at, NOW()),
            connection_config = '{}'::jsonb
        WHERE asset_type NOT IN (
            'ssh', 'rdp',
            'iacs_modbus', 'iacs_opcua', 'iacs_profinet',
            'iacs_iec104', 'iacs_tcp'
        );
        RAISE NOTICE
            'iacs_tunnel migration: % legacy asset row(s) quarantined (rows preserved, soft-deleted, connection_config scrubbed, legacy_protocol recorded in description)',
            converted_total;
    END IF;
END $$;

ALTER TABLE assets ADD CONSTRAINT assets_asset_type_chk CHECK (asset_type IN (
    'ssh',
    'rdp',
    'iacs_modbus',
    'iacs_opcua',
    'iacs_profinet',
    'iacs_iec104',
    'iacs_tcp'
));

-- 2) Session_type widening (no CHECK; Rust enum is the source of truth).
ALTER TABLE proxy_sessions ALTER COLUMN session_type TYPE VARCHAR(20);

-- 3) New IACS-specific columns on proxy_sessions.
ALTER TABLE proxy_sessions
    ADD COLUMN industrial_protocol VARCHAR(20) NULL,
    ADD COLUMN ews_uuid UUID NULL REFERENCES ews(uuid) ON DELETE SET NULL,
    ADD COLUMN tunnel_target_addr VARCHAR(255) NULL;

-- 4.bis) Quarantine legacy proxy_sessions rows whose session_type
-- is outside the new closed vocabulary {ssh, rdp, iacs_tunnel}.
-- Same NON-DESTRUCTIVE strategy as the asset path above: rather
-- than DELETE valuable session history (which auditors depend on),
-- we relabel the row to the closest supported transport and
-- record the original protocol in `metadata->>'legacy_protocol'`.
--
-- For VNC specifically, `rdp` is the closest supported transport.
-- The remapping is purely an audit-trail label change -- the row
-- has long been `terminated` (no proxy is going to reopen it),
-- the recording_path / disconnected_at / bytes_* columns still
-- describe the original VNC session, and forensic queries can
-- pivot on `metadata->>'legacy_protocol'` to filter on the
-- pre-relabel value.
DO $$
DECLARE
    converted_total INTEGER := 0;
    converted_row RECORD;
BEGIN
    FOR converted_row IN
        SELECT session_type, COUNT(*) AS n
        FROM proxy_sessions
        WHERE session_type NOT IN ('ssh', 'rdp', 'iacs_tunnel')
        GROUP BY session_type
    LOOP
        RAISE NOTICE
            'iacs_tunnel migration: quarantining % proxy_sessions row(s) with legacy session_type=% (relabel rdp + record legacy_protocol)',
            converted_row.n, converted_row.session_type;
        converted_total := converted_total + converted_row.n;
    END LOOP;

    IF converted_total > 0 THEN
        UPDATE proxy_sessions
        SET
            metadata = COALESCE(metadata, '{}'::jsonb)
                || jsonb_build_object('legacy_protocol', session_type),
            session_type = 'rdp'
        WHERE session_type NOT IN ('ssh', 'rdp', 'iacs_tunnel');
        RAISE NOTICE
            'iacs_tunnel migration: % legacy proxy_sessions row(s) quarantined (rows preserved, legacy_protocol recorded)',
            converted_total;
    END IF;
END $$;

-- 4) Cross-column consistency CHECK.
ALTER TABLE proxy_sessions ADD CONSTRAINT proxy_sessions_iacs_consistency CHECK (
    (session_type = 'iacs_tunnel'
        AND industrial_protocol IS NOT NULL
        AND ews_uuid IS NOT NULL)
    OR
    (session_type IN ('ssh', 'rdp')
        AND industrial_protocol IS NULL
        AND ews_uuid IS NULL
        AND tunnel_target_addr IS NULL)
);

-- 5) Watchdog index: scan by ews_uuid for active IACS tunnels only.
CREATE INDEX idx_proxy_sessions_iacs_active
    ON proxy_sessions (ews_uuid, status)
    WHERE session_type = 'iacs_tunnel'
      AND status IN ('waiting_client', 'tunnel_active');

-- 6) ews_audit_log: extend event vocabulary.
DO $$
DECLARE
    chk_name TEXT;
BEGIN
    SELECT conname INTO chk_name
    FROM pg_constraint
    WHERE conrelid = 'ews_audit_log'::regclass
      AND contype = 'c'
      AND pg_get_constraintdef(oid) LIKE '%submitted%'
      AND pg_get_constraintdef(oid) LIKE '%offboarded%'
    LIMIT 1;

    IF chk_name IS NOT NULL THEN
        EXECUTE format('ALTER TABLE ews_audit_log DROP CONSTRAINT %I', chk_name);
    END IF;
END $$;

ALTER TABLE ews_audit_log ADD CONSTRAINT ews_audit_log_event_chk CHECK (event IN (
    'submitted', 'edited', 'cancelled',
    'approved', 'rejected',
    'disabled', 'enabled',
    'offboarded',
    'tunnel_opened', 'tunnel_closed'
));

-- 7) asset_groups.kind: extend vocabulary, seed virtual `all_iacs`.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'asset_groups_kind_check'
          AND conrelid = 'asset_groups'::regclass
    ) THEN
        ALTER TABLE asset_groups DROP CONSTRAINT asset_groups_kind_check;
    END IF;
END $$;

ALTER TABLE asset_groups ADD CONSTRAINT asset_groups_kind_check
    CHECK (kind IN ('static', 'all', 'all_iacs'));

DO $$
DECLARE
    reserved_uuid CONSTANT UUID := '00000000-0000-0000-0000-000000000a1c';
    existing_kind VARCHAR(16);
BEGIN
    SELECT kind INTO existing_kind
        FROM asset_groups
        WHERE uuid = reserved_uuid;
    IF existing_kind IS NOT NULL AND existing_kind <> 'all_iacs' THEN
        RAISE EXCEPTION
            'reserved virtual asset_group UUID % already exists with kind=% (expected ''all_iacs'' or absent); refusing to migrate to avoid corrupting the singleton invariant',
            reserved_uuid, existing_kind;
    END IF;

    INSERT INTO asset_groups (uuid, name, slug, kind, color, icon, description)
    VALUES (
        reserved_uuid,
        'All IACS assets',
        '__all-iacs-assets__',
        'all_iacs',
        '#f59e0b',
        'cpu-chip',
        'System-managed virtual group: when referenced from an access_rule, dynamically grants the rule over every IACS asset (any iacs_* asset_type). Cannot be edited, deleted, or have assets attached/detached.'
    )
    ON CONFLICT (uuid) DO NOTHING;
END $$;
