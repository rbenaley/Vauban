-- =============================================================
-- Migration: 20260102000000_initial_schema
-- =============================================================
-- Initial schema for VAUBAN Web
-- This migration creates all necessary tables

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    uuid UUID NOT NULL UNIQUE DEFAULT uuid_generate_v4(),
    username VARCHAR(150) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(150),
    last_name VARCHAR(150),
    phone VARCHAR(20),
    is_active BOOLEAN NOT NULL DEFAULT true,
    is_staff BOOLEAN NOT NULL DEFAULT false,
    is_superuser BOOLEAN NOT NULL DEFAULT false,
    is_service_account BOOLEAN NOT NULL DEFAULT false,
    mfa_enabled BOOLEAN NOT NULL DEFAULT false,
    mfa_enforced BOOLEAN NOT NULL DEFAULT false,
    mfa_secret VARCHAR(255),
    preferences JSONB NOT NULL DEFAULT '{}',
    last_login TIMESTAMPTZ,
    last_login_ip INET,
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ,
    auth_source VARCHAR(10) NOT NULL DEFAULT 'local',
    external_id VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_deleted BOOLEAN NOT NULL DEFAULT false,
    deleted_at TIMESTAMPTZ
);

CREATE INDEX idx_users_uuid ON users(uuid);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_active ON users(is_active) WHERE is_active = true;
CREATE INDEX idx_users_deleted ON users(is_deleted) WHERE is_deleted = false;

-- Vauban Groups table
CREATE TABLE vauban_groups (
    id SERIAL PRIMARY KEY,
    uuid UUID NOT NULL UNIQUE DEFAULT uuid_generate_v4(),
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    source VARCHAR(10) NOT NULL DEFAULT 'local',
    external_id VARCHAR(255),
    parent_id INTEGER REFERENCES vauban_groups(id) ON DELETE SET NULL,
    last_synced TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_vauban_groups_uuid ON vauban_groups(uuid);
CREATE INDEX idx_vauban_groups_name ON vauban_groups(name);

-- User-Group many-to-many
CREATE TABLE user_groups (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id INTEGER NOT NULL REFERENCES vauban_groups(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, group_id)
);

-- Asset Groups table
CREATE TABLE asset_groups (
    id SERIAL PRIMARY KEY,
    uuid UUID NOT NULL UNIQUE DEFAULT uuid_generate_v4(),
    name VARCHAR(100) NOT NULL UNIQUE,
    slug VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    color VARCHAR(7) NOT NULL DEFAULT '#6366f1',
    icon VARCHAR(50) NOT NULL DEFAULT 'folder',
    parent_id INTEGER REFERENCES asset_groups(id) ON DELETE SET NULL,
    created_by_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    updated_by_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_deleted BOOLEAN NOT NULL DEFAULT false,
    deleted_at TIMESTAMPTZ
);

CREATE INDEX idx_asset_groups_uuid ON asset_groups(uuid);
CREATE INDEX idx_asset_groups_slug ON asset_groups(slug);

-- Assets table
CREATE TABLE assets (
    id SERIAL PRIMARY KEY,
    uuid UUID NOT NULL UNIQUE DEFAULT uuid_generate_v4(),
    name VARCHAR(100) NOT NULL,
    hostname VARCHAR(255) NOT NULL,
    ip_address INET,
    port INTEGER NOT NULL DEFAULT 22,
    asset_type VARCHAR(10) NOT NULL DEFAULT 'ssh',
    status VARCHAR(15) NOT NULL DEFAULT 'unknown',
    group_id INTEGER REFERENCES asset_groups(id) ON DELETE SET NULL,
    description TEXT,
    os_type VARCHAR(50),
    os_version VARCHAR(50),
    connection_config JSONB NOT NULL DEFAULT '{}',
    default_credential_id VARCHAR(36),
    require_mfa BOOLEAN NOT NULL DEFAULT false,
    require_justification BOOLEAN NOT NULL DEFAULT false,
    max_session_duration INTEGER NOT NULL DEFAULT 28800,
    last_seen TIMESTAMPTZ,
    created_by_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    updated_by_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_deleted BOOLEAN NOT NULL DEFAULT false,
    deleted_at TIMESTAMPTZ,
    UNIQUE(hostname, port)
);

CREATE INDEX idx_assets_uuid ON assets(uuid);
CREATE INDEX idx_assets_hostname ON assets(hostname);
CREATE INDEX idx_assets_type ON assets(asset_type);
CREATE INDEX idx_assets_status ON assets(status);
CREATE INDEX idx_assets_deleted ON assets(is_deleted) WHERE is_deleted = false;

-- Proxy Sessions table
CREATE TABLE proxy_sessions (
    id SERIAL PRIMARY KEY,
    uuid UUID NOT NULL UNIQUE DEFAULT uuid_generate_v4(),
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    credential_id VARCHAR(36) NOT NULL,
    credential_username VARCHAR(100) NOT NULL,
    session_type VARCHAR(10) NOT NULL,
    status VARCHAR(15) NOT NULL DEFAULT 'pending',
    client_ip INET NOT NULL,
    client_user_agent TEXT,
    proxy_instance VARCHAR(100),
    connected_at TIMESTAMPTZ,
    disconnected_at TIMESTAMPTZ,
    justification TEXT,
    is_recorded BOOLEAN NOT NULL DEFAULT true,
    recording_path VARCHAR(500),
    bytes_sent BIGINT NOT NULL DEFAULT 0,
    bytes_received BIGINT NOT NULL DEFAULT 0,
    commands_count INTEGER NOT NULL DEFAULT 0,
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_proxy_sessions_uuid ON proxy_sessions(uuid);
CREATE INDEX idx_proxy_sessions_user ON proxy_sessions(user_id, created_at DESC);
CREATE INDEX idx_proxy_sessions_asset ON proxy_sessions(asset_id, created_at DESC);
CREATE INDEX idx_proxy_sessions_status ON proxy_sessions(status, created_at DESC);


-- =============================================================
-- Migration: 20260110000000_auth_sessions_and_api_keys
-- =============================================================
-- Add auth_sessions and api_keys tables for user session management and API access

-- Auth Sessions table (tracks active login sessions/JWT tokens)
CREATE TABLE auth_sessions (
    id SERIAL PRIMARY KEY,
    uuid UUID NOT NULL UNIQUE DEFAULT uuid_generate_v4(),
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL,
    ip_address INET NOT NULL,
    user_agent TEXT,
    device_info VARCHAR(255),
    last_activity TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    is_current BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_auth_sessions_uuid ON auth_sessions(uuid);
CREATE INDEX idx_auth_sessions_user ON auth_sessions(user_id, created_at DESC);
CREATE INDEX idx_auth_sessions_token ON auth_sessions(token_hash);
CREATE INDEX idx_auth_sessions_expires ON auth_sessions(expires_at);

-- API Keys table (for programmatic access)
CREATE TABLE api_keys (
    id SERIAL PRIMARY KEY,
    uuid UUID NOT NULL UNIQUE DEFAULT uuid_generate_v4(),
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    key_prefix VARCHAR(8) NOT NULL,
    key_hash VARCHAR(64) NOT NULL,
    scopes JSONB NOT NULL DEFAULT '["read"]',
    last_used_at TIMESTAMPTZ,
    last_used_ip INET,
    expires_at TIMESTAMPTZ,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_api_keys_uuid ON api_keys(uuid);
CREATE INDEX idx_api_keys_user ON api_keys(user_id, created_at DESC);
CREATE INDEX idx_api_keys_prefix ON api_keys(key_prefix);
CREATE INDEX idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX idx_api_keys_active ON api_keys(is_active) WHERE is_active = true;

-- =============================================================
-- Migration: 20260311000000_access_rules
-- =============================================================
-- Access rules: link user groups to asset groups with protocol and time constraints.
-- This table is the core of instance-level authorization in Vauban.

CREATE TABLE access_rules (
    id SERIAL PRIMARY KEY,
    uuid UUID NOT NULL UNIQUE DEFAULT uuid_generate_v4(),
    name VARCHAR(100) NOT NULL,
    description TEXT,
    user_group_id INTEGER NOT NULL REFERENCES vauban_groups(id) ON DELETE CASCADE,
    asset_group_id INTEGER NOT NULL REFERENCES asset_groups(id) ON DELETE CASCADE,
    allowed_protocols TEXT[] NOT NULL DEFAULT '{ssh,rdp}',
    valid_from TIMESTAMPTZ,
    valid_until TIMESTAMPTZ,
    require_mfa BOOLEAN NOT NULL DEFAULT false,
    require_justification BOOLEAN NOT NULL DEFAULT false,
    max_session_duration INTEGER,
    is_active BOOLEAN NOT NULL DEFAULT true,
    priority INTEGER NOT NULL DEFAULT 0,
    created_by_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    updated_by_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_group_id, asset_group_id)
);

CREATE INDEX idx_access_rules_uuid ON access_rules(uuid);
CREATE INDEX idx_access_rules_user_group ON access_rules(user_group_id);
CREATE INDEX idx_access_rules_asset_group ON access_rules(asset_group_id);
CREATE INDEX idx_access_rules_active ON access_rules(is_active) WHERE is_active = true;

-- =============================================================
-- Migration: 20260312000000_drop_asset_group_fk
-- =============================================================
-- Drop FK from assets.group_id to asset_groups(id).
-- The asset_groups table is now managed by vauban-access and may reside
-- in a separate PostgreSQL instance.  The column is kept for lookups but
-- referential integrity is enforced at the application/IPC level.

ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_group_id_fkey;

-- =============================================================
-- Migration: 20260326000000_asset_asset_groups
-- =============================================================
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

-- =============================================================
-- Migration: 20260328000000_jit_access_columns
-- =============================================================
-- Add JIT (Just-In-Time) access columns to proxy_sessions.
-- These support the approval workflow and session duration enforcement.

ALTER TABLE proxy_sessions
    ADD COLUMN approved_by_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN approved_at TIMESTAMPTZ,
    ADD COLUMN max_session_duration INTEGER,
    ADD COLUMN expires_at TIMESTAMPTZ;

CREATE INDEX idx_proxy_sessions_status_pending
    ON proxy_sessions(status) WHERE status = 'pending';

CREATE INDEX idx_proxy_sessions_expires_at
    ON proxy_sessions(expires_at) WHERE expires_at IS NOT NULL AND status = 'active';

-- =============================================================
-- Migration: 20260329000000_refactor_jit_columns
-- =============================================================
-- Rename require_justification to require_approval on access_rules.
-- The flag controls the JIT approval workflow, not just justification text.
ALTER TABLE access_rules RENAME COLUMN require_justification TO require_approval;

-- Remove security constraint columns from assets.
-- These belong on access_rules only (PAM best practice: constraints at rule level).
ALTER TABLE assets DROP COLUMN require_mfa;
ALTER TABLE assets DROP COLUMN require_justification;
ALTER TABLE assets DROP COLUMN max_session_duration;

-- =============================================================
-- Migration: 20260330000000_add_connection_username
-- =============================================================
-- Add connection_username column to assets table.
-- This promotes the username from the connection_config JSONB to a proper column
-- so it can participate in uniqueness constraints.

ALTER TABLE assets
    ADD COLUMN connection_username VARCHAR(100) NOT NULL DEFAULT 'root';

-- Migrate existing usernames from connection_config JSONB
UPDATE assets
SET connection_username = connection_config->>'username'
WHERE connection_config->>'username' IS NOT NULL
  AND connection_config->>'username' != '';

-- Drop the old UNIQUE(hostname, port) constraint
ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_hostname_port_key;

-- Create a partial unique index on (hostname, port, connection_username)
-- that only applies to non-deleted assets. This allows:
--   1. Multiple assets on the same host with different usernames (root@host vs deploy@host)
--   2. Re-creating a deleted asset with the same (hostname, port, username) tuple
CREATE UNIQUE INDEX idx_assets_hostname_port_username_active
    ON assets(hostname, port, connection_username)
    WHERE is_deleted = false;

-- =============================================================
-- Migration: 20260412000000_remove_dead_asset_columns
-- =============================================================
ALTER TABLE assets DROP COLUMN ip_address;
ALTER TABLE assets DROP COLUMN os_type;
ALTER TABLE assets DROP COLUMN os_version;
ALTER TABLE assets DROP COLUMN default_credential_id;
ALTER TABLE assets DROP COLUMN last_seen;

-- =============================================================
-- Migration: 20260418000000_users_last_totp_used_window
-- =============================================================
-- Step-up TOTP replay protection (issue #11 follow-up).
--
-- The Edit User flow now requires the OPERATOR (the person making the
-- request) to confirm any password rotation with a fresh TOTP code from
-- their own authenticator app. Because TOTP_SKEW = 0 (see shared/totp.rs)
-- a code is valid for exactly ONE 30-second window. To prevent an attacker
-- who intercepts a valid code from replaying it within that window on
-- another sensitive operation (RFC 6238 §5.2), we persist the last window
-- consumed by each user and refuse any code whose window has already been
-- recorded as used.
--
-- The value stored is `unix_timestamp_seconds / TOTP_STEP` (i.e. an integer
-- counter that increments once per 30 seconds). NULL means no TOTP code has
-- ever been consumed via the step-up flow yet.
ALTER TABLE users
    ADD COLUMN last_totp_used_window BIGINT NULL;

COMMENT ON COLUMN users.last_totp_used_window IS
    'Last TOTP time-step (unix_seconds / TOTP_STEP) consumed by this user '
    'via the step-up flow. Used to refuse replay of a valid code within its '
    '30-second window. See vauban-web/src/services/auth.rs::verify_and_consume_totp.';

-- =============================================================
-- Migration: 20260419000000_dedupe_and_uniq_auth_sessions
-- =============================================================
-- Issue #8: dedupe login sessions and enforce a per-(user, device, IP) invariant.
--
-- Background: each web login inserted a new row in `auth_sessions` without
-- ever invalidating older rows for the same browser/IP combination. As a
-- result, "My Sessions" displayed the same physical device as N independent
-- entries -- one per past login that had not yet hit `expires_at`. This
-- migration cleans up the historical pollution and adds a unique index that
-- makes the duplication structurally impossible going forward, in tandem
-- with the application-level purge performed at login time
-- (vauban-web/src/handlers/auth.rs::purge_sessions_for_device).

-- Step 1: normalise `device_info` so it can take part in a deterministic
-- UNIQUE index. PostgreSQL treats two NULLs as distinct in unique indexes
-- (without NULLS NOT DISTINCT, PG15+), which would let duplicates slip
-- through whenever the User-Agent header was missing.
UPDATE auth_sessions SET device_info = 'Unknown browser' WHERE device_info IS NULL;
ALTER TABLE auth_sessions ALTER COLUMN device_info SET NOT NULL;
ALTER TABLE auth_sessions ALTER COLUMN device_info SET DEFAULT 'Unknown browser';

-- Step 2: dedupe existing rows. For each (user_id, device_info, ip_address)
-- group, keep the row with the most recent `last_activity` (ties broken by
-- the highest `id`) and delete the rest.
DELETE FROM auth_sessions a
USING auth_sessions b
WHERE a.user_id = b.user_id
  AND a.device_info = b.device_info
  AND a.ip_address = b.ip_address
  AND (a.last_activity, a.id) < (b.last_activity, b.id);

-- Step 3: prophylactic purge of long-idle rows so we start from a clean
-- baseline (mirrors what the periodic cleanup task will do from now on).
DELETE FROM auth_sessions
WHERE last_activity < NOW() - INTERVAL '24 hours';

-- Step 4: enforce the invariant -- at most one live session per
-- (user, device, IP). Combined with the application-level DELETE before
-- INSERT (B) and the cleanup task (C), this guarantees the My Sessions
-- view never shows the same device twice.
CREATE UNIQUE INDEX uniq_auth_sessions_per_device
    ON auth_sessions (user_id, device_info, ip_address);

-- Step 5: index supporting the cleanup task's idle-timeout DELETE.
CREATE INDEX idx_auth_sessions_last_activity
    ON auth_sessions (last_activity);

COMMENT ON INDEX uniq_auth_sessions_per_device IS
    'Issue #8: enforce at most one live login session per (user, device, IP). '
    'Maintained by handlers::auth (DELETE before INSERT in a transaction) '
    'and tasks::cleanup (deletes expired and idle sessions).';

-- =============================================================
-- Migration: 20260420000000_assets_irreversible_delete
-- =============================================================
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

-- =============================================================
-- Migration: 20260424000000_virtual_asset_group_all
-- =============================================================
-- Virtual "All assets" asset_group: a single, system-managed row that, when
-- referenced from an access_rule, dynamically grants the rule over EVERY
-- non-deleted asset (subject to the rule's allowed_protocols / validity).
--
-- Design properties pinned by this migration:
--   1. The `kind` column tags the row's nature ('static' = ordinary user-
--      managed group; 'all' = the singleton virtual group).
--   2. A partial UNIQUE index guarantees AT MOST ONE row per non-static kind
--      (currently only 'all'; the column is left open for future kinds like
--      'all_ssh' / 'all_rdp' but no extra rows are seeded today).
--   3. A trigger on asset_asset_groups blocks every INSERT/UPDATE that would
--      attach an asset to a virtual group -- the virtual row MUST stay
--      empty in asset_asset_groups (its semantics is "everything", not "a
--      specific list").
--   4. A trigger on asset_groups itself blocks every UPDATE/DELETE on a
--      non-static row -- including the soft-delete path. The virtual row
--      cannot be renamed, recolored, soft-deleted, hard-deleted, or
--      flipped to kind='static'.
--
-- Both triggers identify the virtual row by `kind`, NOT by the seeded UUID,
-- so a future migration that re-seeds the row with a different UUID keeps
-- every defense intact.
--
-- Recovery procedure if the virtual row is missing at boot (vauban-access /
-- vauban-web fail-loud): re-run this migration; the seed INSERT is
-- ON CONFLICT-safe so it acts as an idempotent self-heal.

ALTER TABLE asset_groups
    ADD COLUMN kind VARCHAR(16) NOT NULL DEFAULT 'static';

ALTER TABLE asset_groups
    ADD CONSTRAINT asset_groups_kind_check
    CHECK (kind IN ('static', 'all'));

-- Partial unique index: at most one row may exist per non-'static' kind.
-- The current vocabulary has only 'all'; adding e.g. 'all_ssh' later will
-- automatically be subject to the same singleton constraint.
CREATE UNIQUE INDEX uniq_asset_groups_kind_singleton
    ON asset_groups (kind)
    WHERE kind <> 'static';

-- Defense-in-depth: forbid any membership row that targets a virtual group.
-- Triggered BEFORE INSERT and BEFORE UPDATE so an attempt to re-point an
-- existing membership at the virtual row is also caught.
CREATE OR REPLACE FUNCTION block_membership_on_virtual_groups()
RETURNS TRIGGER AS $$
DECLARE
    target_kind VARCHAR(16);
BEGIN
    SELECT kind INTO target_kind
        FROM asset_groups
        WHERE id = NEW.asset_group_id;
    IF target_kind IS NOT NULL AND target_kind <> 'static' THEN
        RAISE EXCEPTION
            'cannot add members to virtual asset_group (id=%, kind=%)',
            NEW.asset_group_id, target_kind
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER block_membership_on_virtual_groups_insert
    BEFORE INSERT ON asset_asset_groups
    FOR EACH ROW EXECUTE FUNCTION block_membership_on_virtual_groups();

CREATE TRIGGER block_membership_on_virtual_groups_update
    BEFORE UPDATE ON asset_asset_groups
    FOR EACH ROW EXECUTE FUNCTION block_membership_on_virtual_groups();

-- Defense-in-depth: forbid any UPDATE/DELETE on a non-static asset_groups
-- row. Covers rename, recolor, soft-delete (is_deleted=true), hard delete,
-- and the kind flip-flop attack (UPDATE SET kind='static' WHERE kind='all').
CREATE OR REPLACE FUNCTION block_mutation_on_virtual_groups()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.kind <> 'static' THEN
            RAISE EXCEPTION
                'cannot delete virtual asset_group (id=%, kind=%, uuid=%)',
                OLD.id, OLD.kind, OLD.uuid
                USING ERRCODE = 'check_violation';
        END IF;
        RETURN OLD;
    ELSIF TG_OP = 'UPDATE' THEN
        IF OLD.kind <> 'static' THEN
            RAISE EXCEPTION
                'cannot update virtual asset_group (id=%, kind=%, uuid=%)',
                OLD.id, OLD.kind, OLD.uuid
                USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER block_mutation_on_virtual_groups_update
    BEFORE UPDATE ON asset_groups
    FOR EACH ROW EXECUTE FUNCTION block_mutation_on_virtual_groups();

CREATE TRIGGER block_mutation_on_virtual_groups_delete
    BEFORE DELETE ON asset_groups
    FOR EACH ROW EXECUTE FUNCTION block_mutation_on_virtual_groups();

-- Seed the singleton virtual group. Reserved UUID has the mnemonic suffix
-- '0a11' (= "all"). The slug starts with '__' to make it obvious in any
-- ad-hoc query that this row is system-managed and not user-editable.
--
-- Idempotent: ON CONFLICT DO NOTHING means re-running the migration after
-- a partial restore acts as a self-heal. If the reserved UUID already
-- exists with kind='static', the partial UNIQUE index would NOT catch
-- that case -- so we guard it explicitly and fail loud:
DO $$
DECLARE
    reserved_uuid CONSTANT UUID := '00000000-0000-0000-0000-000000000a11';
    existing_kind VARCHAR(16);
BEGIN
    SELECT kind INTO existing_kind
        FROM asset_groups
        WHERE uuid = reserved_uuid;
    IF existing_kind IS NOT NULL AND existing_kind <> 'all' THEN
        RAISE EXCEPTION
            'reserved virtual asset_group UUID % already exists with kind=% (expected ''all'' or absent); refusing to migrate to avoid corrupting the singleton invariant',
            reserved_uuid, existing_kind;
    END IF;

    INSERT INTO asset_groups (uuid, name, slug, kind, color, icon, description)
    VALUES (
        reserved_uuid,
        'All assets',
        '__all-assets__',
        'all',
        '#6366f1',
        'globe',
        'System-managed virtual group: when referenced from an access_rule, dynamically grants the rule over every non-deleted asset. Cannot be edited, deleted, or have assets attached/detached.'
    )
    ON CONFLICT (uuid) DO NOTHING;
END $$;

-- =============================================================
-- Migration: 20260425000000_approval_audit_and_sod
-- =============================================================
-- Approval audit + Separation of Duties (SoD) for the JIT access workflow.
--
-- Two security invariants are pinned at the DB layer (the hard floor of
-- defense-in-depth, non-bypassable even from a raw psql session or a bug in
-- vauban-web / vauban-access):
--
--   1. Separation of duties on `proxy_sessions`: the user who approves (or
--      rejects) a request MUST NOT be the requester. Two CHECK constraints
--      enforce `approved_by_id <> user_id` and `rejected_by_id <> user_id`
--      atomically on every INSERT and UPDATE.
--
--   2. Append-only audit log: every approval/rejection decision spawns one
--      row in `approval_audit_log`. A BEFORE UPDATE OR DELETE trigger raises
--      `EXCEPTION 'approval_audit_log is append-only'` so the trail cannot
--      be rewritten by app bugs nor by a non-superuser DBA.
--
-- Snapshots: the audit row denormalises actor / requester usernames and the
-- asset name at decision time. This guarantees the trail stays meaningful
-- even after a later soft/hard delete of the user or asset (the FKs use
-- ON DELETE SET NULL so the row is preserved).
--
-- Recovery: the runbook docs/runbooks/approval_audit.md describes how to
-- query the trail, export to CSV for compliance, and recover from
-- mono-admin lockout (provisioning a second administrator).

-- 1) Reject-side columns (the approve-side already exists from
--    20260328000000_jit_access_columns).
ALTER TABLE proxy_sessions
    ADD COLUMN rejected_by_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN rejected_at TIMESTAMPTZ,
    ADD COLUMN decision_reason TEXT NULL;

-- 2) Backfill: clear self-approval / self-rejection references created
--    before SoD was enforced. These are historical rows where the admin
--    approved their own request (legal at the time). We NULL-out the
--    actor FK so the CHECK below can be applied cleanly. The session
--    status and timestamps are preserved — only the "who decided" link
--    is severed for those legacy rows.
UPDATE proxy_sessions
    SET approved_by_id = NULL
    WHERE approved_by_id IS NOT NULL AND approved_by_id = user_id;

UPDATE proxy_sessions
    SET rejected_by_id = NULL
    WHERE rejected_by_id IS NOT NULL AND rejected_by_id = user_id;

-- 3) Separation of Duties: the approver/rejecter must be a different user
--    than the requester. Both constraints accept NULL on the actor side
--    (no decision yet) but reject any row that would make the actor and
--    the requester the same person.
ALTER TABLE proxy_sessions
    ADD CONSTRAINT approval_separation_of_duties
    CHECK (approved_by_id IS NULL OR approved_by_id <> user_id);

ALTER TABLE proxy_sessions
    ADD CONSTRAINT rejection_separation_of_duties
    CHECK (rejected_by_id IS NULL OR rejected_by_id <> user_id);

-- 4) Append-only audit log. One row per approval decision (approve or
--    reject). Snapshots the actor/requester usernames and asset name so
--    the trail survives later user/asset deletions.
CREATE TABLE approval_audit_log (
    id BIGSERIAL PRIMARY KEY,
    session_uuid UUID NOT NULL,
    decision VARCHAR(8) NOT NULL CHECK (decision IN ('approve', 'reject')),
    actor_user_id INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
    actor_username VARCHAR(150) NOT NULL,
    requester_user_id INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
    requester_username VARCHAR(150) NOT NULL,
    asset_uuid UUID NOT NULL,
    asset_name VARCHAR(200) NOT NULL,
    protocol VARCHAR(10),
    duration_override_seconds INTEGER NULL,
    decision_reason TEXT NULL,
    decision_ip INET NULL,
    decision_user_agent TEXT NULL,
    request_id VARCHAR(64) NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 5) Append-only invariant: any UPDATE or DELETE on this table raises.
--    Insertions are the only legitimate write path. Even DBAs without
--    superuser bypass cannot rewrite the audit history without explicitly
--    DROP'ing the trigger first (a loud, auditable action by itself).
--
--    Exception: FK cascaded SET NULL (user deletion) is allowed because
--    it only touches the nullable FK columns (actor_user_id,
--    requester_user_id) without altering any audit-significant field.
--    The snapshotted usernames and all other fields are preserved.
CREATE OR REPLACE FUNCTION block_approval_audit_log_mutation()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION
            'approval_audit_log is append-only (DELETE on id=% rejected)',
            OLD.id
            USING ERRCODE = 'check_violation';
    ELSIF TG_OP = 'UPDATE' THEN
        -- Allow FK cascaded SET NULL on the two user-id columns.
        -- Every other column change is blocked.
        IF ROW(NEW.id, NEW.session_uuid, NEW.decision,
               NEW.actor_username, NEW.requester_username,
               NEW.asset_uuid, NEW.asset_name, NEW.protocol,
               NEW.duration_override_seconds, NEW.decision_reason,
               NEW.decision_ip, NEW.decision_user_agent,
               NEW.request_id, NEW.created_at)
           IS DISTINCT FROM
           ROW(OLD.id, OLD.session_uuid, OLD.decision,
               OLD.actor_username, OLD.requester_username,
               OLD.asset_uuid, OLD.asset_name, OLD.protocol,
               OLD.duration_override_seconds, OLD.decision_reason,
               OLD.decision_ip, OLD.decision_user_agent,
               OLD.request_id, OLD.created_at)
        THEN
            RAISE EXCEPTION
                'approval_audit_log is append-only (UPDATE on id=% rejected)',
                OLD.id
                USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER block_approval_audit_log_update
    BEFORE UPDATE ON approval_audit_log
    FOR EACH ROW EXECUTE FUNCTION block_approval_audit_log_mutation();

CREATE TRIGGER block_approval_audit_log_delete
    BEFORE DELETE ON approval_audit_log
    FOR EACH ROW EXECUTE FUNCTION block_approval_audit_log_mutation();

-- 6) Indexes for the typical query patterns:
--    * by session (the detail page joins audit rows back to a session)
--    * by actor (the /audit/approvals page filters by approver)
--    * by requester (compliance: "who approved my access?")
CREATE INDEX idx_approval_audit_log_session_uuid
    ON approval_audit_log (session_uuid);

CREATE INDEX idx_approval_audit_log_actor
    ON approval_audit_log (actor_user_id, created_at DESC);

CREATE INDEX idx_approval_audit_log_requester
    ON approval_audit_log (requester_user_id, created_at DESC);

-- =============================================================
-- Migration: 20260430000000_recording_integrity_metadata
-- =============================================================
-- Recording integrity metadata persisted on `proxy_sessions`.
--
-- Until now the BLAKE3 hash, file size, duration, terminal/screen geometry
-- and segment count of every recording lived only on disk in `meta.json`,
-- written by `vauban-audit` at session end. The new "Recording Details"
-- page surfaces this data on every render, and we want to avoid an
-- I/O round-trip + JSON parse on every GET. We therefore precompute the
-- bundle once into `proxy_sessions` via a lazy background hydrator
-- (vauban-web/src/services/recording_hydrator.rs) and the page becomes a
-- pure SELECT.
--
-- Format unification: SSH stores a single hash of the `.cast` file, but
-- RDP records one hash per fragmented-MP4 segment. The hydrator computes
-- BLAKE3(concat(segment_hashes_hex)) for RDP so this column has uniform
-- semantics regardless of protocol.
--
-- The columns are all NULL-able because:
--   1. Pre-existing rows from before this migration must remain valid.
--   2. The hydrator runs asynchronously after session disconnect; rows
--      sit unfinalized for a few seconds. The detail page handles the
--      `None` state by showing "Integrity metadata pending finalization".
--
-- A partial index on the unfinalized subset keeps the hydrator's
-- batch-scan cheap as the recordings table grows.

ALTER TABLE proxy_sessions
    ADD COLUMN recording_blake3 VARCHAR(64),
    ADD COLUMN recording_size_bytes BIGINT,
    ADD COLUMN recording_duration_ms BIGINT,
    ADD COLUMN recording_event_count INTEGER,
    ADD COLUMN recording_format VARCHAR(32),
    ADD COLUMN recording_width SMALLINT,
    ADD COLUMN recording_height SMALLINT,
    ADD COLUMN recording_segment_count INTEGER,
    ADD COLUMN recording_codec VARCHAR(64),
    ADD COLUMN recording_finalized_at TIMESTAMPTZ;

-- BLAKE3 hex format invariant: the column is either NULL or exactly 64
-- lowercase hex characters. This rules out partial writes and uppercase
-- variants (BLAKE3.to_hex() is lowercase) at the DB layer.
ALTER TABLE proxy_sessions
    ADD CONSTRAINT recording_blake3_format
        CHECK (recording_blake3 IS NULL OR recording_blake3 ~ '^[0-9a-f]{64}$');

-- Recording format enum: pinned to the three formats the hydrator knows
-- how to produce. Adding a new format requires bumping this constraint
-- AND the hydrator's parser.
ALTER TABLE proxy_sessions
    ADD CONSTRAINT recording_format_enum
        CHECK (recording_format IS NULL
               OR recording_format IN ('asciicast-v2', 'fmp4-dash', 'fmp4-flat'));

-- Partial index for the hydrator's batch-scan query. Only rows that are
-- recorded, have a path on disk, and have NOT been finalized yet are
-- candidates. The index stays small because finalized rows leave it
-- (PostgreSQL prunes them automatically thanks to the WHERE clause).
CREATE INDEX idx_proxy_sessions_pending_finalization
    ON proxy_sessions (created_at)
    WHERE is_recorded = TRUE
      AND recording_path IS NOT NULL
      AND recording_finalized_at IS NULL;

-- =============================================================
-- Migration: 20260501000000_email_outbox
-- =============================================================
-- Email outbox for the Vauban notification system (Issue #10).
--
-- Pattern: transactional outbox. The application writes one row per
-- notification event in the SAME database transaction as the business
-- mutation that triggers it (e.g. UPDATE proxy_sessions SET status='approved'
-- and INSERT email_outbox in the same BEGIN/COMMIT). This guarantees:
--
--   * At-least-once delivery: if the business commit succeeds, the email
--     row is durable and will eventually be picked up by the dispatcher.
--   * Atomicity: a rollback of the business mutation cancels the email.
--   * Idempotence: each event has a UUID `event_id` enforced UNIQUE; a
--     replay by a buggy handler is rejected at INSERT time.
--
-- The dispatcher (vauban-web/src/tasks/mailer.rs) polls this table with
-- `SELECT ... FOR UPDATE SKIP LOCKED LIMIT N` so multiple workers (today
-- one, tomorrow several) can drain in parallel without double-sends.
--
-- Defense-in-depth header sanitization: the application MUST refuse any
-- recipient/subject containing CR or LF (anti-injection), but we also
-- pin a CHECK at the DB layer as a hard floor. Even a buggy or
-- compromised application cannot persist a header-injection payload.
CREATE TABLE email_outbox (
    id BIGSERIAL PRIMARY KEY,
    -- Idempotence key: caller-generated UUIDv4. INSERT collides on
    -- duplicate event_id so a retried handler does not enqueue twice.
    event_id UUID NOT NULL,
    -- Event taxonomy (e.g. "access_request.submitted", "user.created").
    -- Used for filtering, rate-limiting per kind, and template lookup.
    event_kind VARCHAR(64) NOT NULL,
    -- RFC 5321 maximum is 254 (local-part 64 + "@" + domain 253). We
    -- store up to 320 chars for safety with comments.
    recipient VARCHAR(320) NOT NULL,
    -- Display name for the recipient (rendered as "Name <email>").
    -- Optional (empty string == bare address).
    recipient_name VARCHAR(255) NOT NULL DEFAULT '',
    -- Subject line. RFC 2822 limits "unfolded" lines to 998 chars; we
    -- clamp to 200 for sanity. The CHECK below forbids CR/LF.
    subject VARCHAR(200) NOT NULL,
    -- text/plain body (mandatory). text/html body (optional, multipart).
    body_text TEXT NOT NULL,
    body_html TEXT,
    -- Lifecycle: pending -> (sent | failed | cancelled).
    status VARCHAR(16) NOT NULL DEFAULT 'pending',
    -- Retry bookkeeping. A pending row is eligible when
    -- next_retry_at <= NOW() (or NULL = ready immediately).
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 5,
    next_retry_at TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sent_at TIMESTAMPTZ,
    -- Status whitelist enforced at the DB layer.
    CONSTRAINT email_outbox_status_valid
        CHECK (status IN ('pending', 'sent', 'failed', 'cancelled')),
    -- Idempotence enforced at the DB layer.
    CONSTRAINT email_outbox_event_id_unique
        UNIQUE (event_id),
    -- Anti-CRLF injection (defense-in-depth, the application MUST also
    -- sanitize before INSERT). strpos returns >0 if the substring exists.
    CONSTRAINT email_outbox_no_crlf_recipient
        CHECK (strpos(recipient, E'\r') = 0 AND strpos(recipient, E'\n') = 0),
    CONSTRAINT email_outbox_no_crlf_recipient_name
        CHECK (strpos(recipient_name, E'\r') = 0 AND strpos(recipient_name, E'\n') = 0),
    CONSTRAINT email_outbox_no_crlf_subject
        CHECK (strpos(subject, E'\r') = 0 AND strpos(subject, E'\n') = 0),
    -- Sanity bounds.
    CONSTRAINT email_outbox_attempts_nonneg
        CHECK (attempts >= 0 AND max_attempts > 0),
    CONSTRAINT email_outbox_recipient_nonempty
        CHECK (length(recipient) > 0),
    CONSTRAINT email_outbox_subject_nonempty
        CHECK (length(subject) > 0)
);

-- Hot-path index for the dispatcher's "pick the next batch" query.
-- Partial index keeps it small (only pending rows are interesting).
CREATE INDEX idx_email_outbox_pending_due
    ON email_outbox (next_retry_at NULLS FIRST, id)
    WHERE status = 'pending';

-- Index for operator queries on the admin status page (future PR).
CREATE INDEX idx_email_outbox_status_created
    ON email_outbox (status, created_at DESC);

-- Index for retry/audit queries by event kind (e.g. "show me the last
-- 50 access_request.approved emails").
CREATE INDEX idx_email_outbox_event_kind_created
    ON email_outbox (event_kind, created_at DESC);

-- =============================================================
-- Migration: 20260506000000_iacs_ews_onboarding
-- =============================================================
-- IACS / Engineering Workstation (EWS) onboarding -- preliminary scaffolding.
--
-- This migration introduces the data model for the IACS section: industrial
-- operators ("EWS owners") submit onboarding requests for their workstations
-- (laptop / desktop running an SSH client used to reach future IACS assets);
-- administrators then approve, reject, disable, re-enable, or offboard them.
--
-- The schema mirrors the JIT access pattern shipped in
-- 20260425000000_approval_audit_and_sod (deux tables + audit append-only):
--
--   1. ews_onboarding_requests -- pending / approved / rejected / cancelled
--      lifecycle. A row stays for the entire request history (a request can
--      be edited while pending, cancelled by the requester, or decided by an
--      admin). Once approved, the matching `ews` row is created in the same
--      transaction (vauban-access enforces atomicity).
--
--   2. ews -- the approved EWS. Holds the active SSH public key, plus
--      disable / offboard soft-delete columns. Offboarded rows are kept for
--      audit (FK target of `ews_audit_log`) but never become active again
--      (offboarding is irreversible by design).
--
--   3. ews_audit_log -- append-only trail of every state transition (submit,
--      edit, cancel, approve, reject, disable, enable, offboard). Same
--      `block_*_mutation` trigger pattern as `approval_audit_log` so a
--      compromised app or a non-superuser DBA cannot rewrite history.
--
-- Snapshots: actor / target usernames and EWS name are denormalised at write
-- time so the trail survives later user soft-deletes (FKs use ON DELETE SET
-- NULL on the user-id columns; snapshots stay).
--
-- Defense-in-depth: an additional partial unique index on `ews` enforces
-- "one active fingerprint at a time" at the DB layer. The advisory check at
-- form-submit time exists in vauban-web for UX (immediate 400 with a clear
-- message), but the DB index is the authoritative gate.

-- 1) Onboarding requests. Status transitions:
--    pending -> approved  (admin RecordEwsDecision Approve)
--    pending -> rejected  (admin RecordEwsDecision Reject; reason required)
--    pending -> cancelled (requester CancelEwsRequest)
--    The row is never deleted, never UPDATEd back to pending after a final
--    decision (CHECK below). Re-submissions create a NEW request row with a
--    fresh uuid; the original row stays for audit.
CREATE TABLE ews_onboarding_requests (
    id BIGSERIAL PRIMARY KEY,
    uuid UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    name VARCHAR(128) NOT NULL,
    public_key TEXT NOT NULL,
    public_key_fingerprint VARCHAR(64) NOT NULL,
    key_algo VARCHAR(40) NOT NULL,
    justification VARCHAR(250) NOT NULL,
    status VARCHAR(10) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'rejected', 'cancelled')),
    decision_reason TEXT NULL,
    decided_by_id INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
    decided_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ews_request_decision_consistency CHECK (
        (status = 'pending' AND decided_by_id IS NULL AND decided_at IS NULL)
        OR
        (status IN ('approved', 'cancelled') AND decided_at IS NOT NULL)
        OR
        (status = 'rejected' AND decided_at IS NOT NULL AND decision_reason IS NOT NULL)
    )
);

CREATE INDEX idx_ews_onboarding_requests_status
    ON ews_onboarding_requests (status);

CREATE INDEX idx_ews_onboarding_requests_user
    ON ews_onboarding_requests (user_id, status, created_at DESC);

CREATE INDEX idx_ews_onboarding_requests_fingerprint_pending
    ON ews_onboarding_requests (public_key_fingerprint)
    WHERE status = 'pending';

-- 2) Approved EWS. State derived from disabled_at / offboarded_at:
--      both NULL                       -> active
--      disabled_at IS NOT NULL, ...    -> disabled (reversible by enable)
--      offboarded_at IS NOT NULL       -> offboarded (irreversible soft-delete)
--    A disabled EWS keeps the fingerprint locked (an admin may re-enable
--    later and we don't want a stranger to grab the key meanwhile). Only
--    offboarding releases the fingerprint -- enforced by the partial unique
--    index below.
CREATE TABLE ews (
    id BIGSERIAL PRIMARY KEY,
    uuid UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    request_uuid UUID NOT NULL UNIQUE
        REFERENCES ews_onboarding_requests(uuid) ON DELETE RESTRICT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    name VARCHAR(128) NOT NULL,
    public_key TEXT NOT NULL,
    public_key_fingerprint VARCHAR(64) NOT NULL,
    key_algo VARCHAR(40) NOT NULL,
    disabled_by_id INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
    disabled_at TIMESTAMPTZ NULL,
    offboarded_by_id INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
    offboarded_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ews_disabled_consistency CHECK (
        (disabled_at IS NULL AND disabled_by_id IS NULL)
        OR
        (disabled_at IS NOT NULL)
    ),
    CONSTRAINT ews_offboarded_consistency CHECK (
        (offboarded_at IS NULL AND offboarded_by_id IS NULL)
        OR
        (offboarded_at IS NOT NULL)
    )
);

-- One active fingerprint at a time. Covers active + disabled rows; only
-- offboarded rows release the fingerprint, which matches the spec:
--   - the user can re-submit the same key after offboarding,
--   - but two simultaneous active EWS cannot share a key.
CREATE UNIQUE INDEX ews_active_fingerprint_uniq
    ON ews (public_key_fingerprint)
    WHERE offboarded_at IS NULL;

CREATE INDEX idx_ews_user
    ON ews (user_id, created_at DESC);

-- 3) Append-only audit log. One row per state transition.
--    Snapshot fields denormalise the actor / target usernames and the EWS
--    name at decision time so the trail survives later user soft-delete.
CREATE TABLE ews_audit_log (
    id BIGSERIAL PRIMARY KEY,
    ews_uuid UUID NULL,
    request_uuid UUID NULL,
    event VARCHAR(20) NOT NULL CHECK (event IN (
        'submitted', 'edited', 'cancelled',
        'approved', 'rejected',
        'disabled', 'enabled',
        'offboarded'
    )),
    actor_user_id INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
    actor_username VARCHAR(150) NOT NULL,
    target_user_id INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
    target_username VARCHAR(150) NOT NULL,
    ews_name VARCHAR(128) NOT NULL,
    public_key_fingerprint VARCHAR(64) NOT NULL,
    decision_reason TEXT NULL,
    actor_ip INET NULL,
    request_id VARCHAR(64) NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ews_audit_log_event_targets_at_least_one CHECK (
        ews_uuid IS NOT NULL OR request_uuid IS NOT NULL
    )
);

-- 4) Append-only invariant -- same pattern as `block_approval_audit_log_mutation`.
--    UPDATE / DELETE are rejected, except for the FK cascaded SET NULL on
--    actor_user_id / target_user_id (snapshot usernames are preserved).
CREATE OR REPLACE FUNCTION block_ews_audit_log_mutation()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION
            'ews_audit_log is append-only (DELETE on id=% rejected)',
            OLD.id
            USING ERRCODE = 'check_violation';
    ELSIF TG_OP = 'UPDATE' THEN
        IF ROW(NEW.id, NEW.ews_uuid, NEW.request_uuid, NEW.event,
               NEW.actor_username, NEW.target_username,
               NEW.ews_name, NEW.public_key_fingerprint,
               NEW.decision_reason, NEW.actor_ip,
               NEW.request_id, NEW.created_at)
           IS DISTINCT FROM
           ROW(OLD.id, OLD.ews_uuid, OLD.request_uuid, OLD.event,
               OLD.actor_username, OLD.target_username,
               OLD.ews_name, OLD.public_key_fingerprint,
               OLD.decision_reason, OLD.actor_ip,
               OLD.request_id, OLD.created_at)
        THEN
            RAISE EXCEPTION
                'ews_audit_log is append-only (UPDATE on id=% rejected)',
                OLD.id
                USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER block_ews_audit_log_update
    BEFORE UPDATE ON ews_audit_log
    FOR EACH ROW EXECUTE FUNCTION block_ews_audit_log_mutation();

CREATE TRIGGER block_ews_audit_log_delete
    BEFORE DELETE ON ews_audit_log
    FOR EACH ROW EXECUTE FUNCTION block_ews_audit_log_mutation();

CREATE INDEX idx_ews_audit_log_ews_uuid
    ON ews_audit_log (ews_uuid)
    WHERE ews_uuid IS NOT NULL;

CREATE INDEX idx_ews_audit_log_request_uuid
    ON ews_audit_log (request_uuid)
    WHERE request_uuid IS NOT NULL;

CREATE INDEX idx_ews_audit_log_actor
    ON ews_audit_log (actor_user_id, created_at DESC);

CREATE INDEX idx_ews_audit_log_target
    ON ews_audit_log (target_user_id, created_at DESC);

-- =============================================================
-- Migration: 20260508000000_iacs_tunnel
-- =============================================================
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

-- =============================================================
-- Migration: 20260509000000_recording_retention_index
-- =============================================================
CREATE INDEX idx_proxy_sessions_recording_retention
    ON proxy_sessions (disconnected_at ASC)
    WHERE is_recorded = TRUE
      AND recording_path IS NOT NULL
      AND disconnected_at IS NOT NULL;

-- =============================================================
-- Migration: 20260510000000_recording_pcap_bundle
-- =============================================================
-- Allow pcap-bundle as a persisted recording_format (IACS PCAP archive).
ALTER TABLE proxy_sessions
    DROP CONSTRAINT IF EXISTS recording_format_enum;

ALTER TABLE proxy_sessions
    ADD CONSTRAINT recording_format_enum
        CHECK (recording_format IS NULL
               OR recording_format IN (
                   'asciicast-v2',
                   'fmp4-dash',
                   'fmp4-flat',
                   'pcap-bundle'
               ));

-- =============================================================
-- Migration: 20260513000000_mfa_pending_secret
-- =============================================================
-- VAU-008: split GET/POST /mfa/setup with a pending TOTP secret.
--
-- The candidate TOTP secret generated during the (CSRF + password step-up
-- gated) `POST /mfa/setup/init` step lives in `pending_mfa_secret` until the
-- user confirms a valid code via `POST /mfa/setup`; only then is it promoted
-- to `users.mfa_secret`. Keeping the candidate OUT of `mfa_secret` guarantees:
--   * a GET can never (re)bind a second factor (no side effect), and
--   * a generation never overwrites an already-enrolled `mfa_secret`.
-- `pending_mfa_generated_at` lets the confirm step expire a stale candidate.
ALTER TABLE users
    ADD COLUMN pending_mfa_secret VARCHAR(255) NULL,
    ADD COLUMN pending_mfa_generated_at TIMESTAMPTZ NULL;

COMMENT ON COLUMN users.pending_mfa_secret IS
    'Candidate TOTP secret (vault envelope vN:...) awaiting confirmation via '
    'POST /mfa/setup. Promoted to mfa_secret only after a valid TOTP code. '
    'See VAU-008 / vauban-web/src/handlers/auth.rs::mfa_setup_init.';

COMMENT ON COLUMN users.pending_mfa_generated_at IS
    'UTC timestamp when pending_mfa_secret was generated; used to expire a '
    'stale candidate at confirmation time (TTL).';

-- =============================================================
-- Migration: 20260614000000_drop_pending_mfa_secret
-- =============================================================
-- VAU-008 (ephemeral variant): drop the per-user pending MFA columns.
--
-- The candidate TOTP secret is no longer persisted in `users`. It now lives in
-- a process-local, per-session in-memory store (see
-- vauban-web/src/services/pending_mfa.rs) so that:
--   * it is never written to the database before enrolment confirmation, and
--   * two distinct login sessions of the same account get distinct candidates
--     (the previous column was shared across all sessions of a user).
ALTER TABLE users
    DROP COLUMN IF EXISTS pending_mfa_generated_at,
    DROP COLUMN IF EXISTS pending_mfa_secret;

-- =============================================================
-- Migration: 20260625000000_assets_relax_uniqueness_to_name
-- =============================================================
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

-- =============================================================
-- Migration: 20260628000000_users_username_case_insensitive
-- =============================================================
-- Vauban login identifiers are case-insensitive: `Alice`, `alice` and
-- `ALICE` denote the same account. Until now the `username` column was a
-- plain case-sensitive VARCHAR UNIQUE and the login lookup did an exact
-- (byte-for-byte) match, so an account created as `Admin` could not log
-- in by typing `admin`, and the LDAP just-in-time path could even mint a
-- second shadow row for a different-cased spelling of the same identity.
--
-- This migration canonicalises the stored identity and pins the
-- case-insensitive uniqueness at the database layer (defence in depth:
-- even a future code path that forgets to normalise the identifier cannot
-- create a case-variant duplicate).

-- 1) Canonicalise every existing username to its lower-cased form.
--    This fails loudly (unique_violation on the existing UNIQUE(username)
--    constraint) if two rows differ only by case: silently merging two
--    distinct identities would be a security defect, so an operator must
--    resolve such a collision by hand before re-running the migration.
UPDATE users
SET username = lower(username)
WHERE username <> lower(username);

-- 2) Enforce case-insensitive uniqueness going forward. The index is
--    non-partial to mirror the existing column-level UNIQUE semantics:
--    soft-deleted rows retire their username with a `_deleted_<ts>`
--    suffix (all lower-case), which keeps the lower(username) value
--    unique as well, so deleted spellings remain reusable.
CREATE UNIQUE INDEX idx_users_username_lower ON users (lower(username));

