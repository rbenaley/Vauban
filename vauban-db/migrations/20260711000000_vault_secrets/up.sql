-- Organisational vault secrets + group-to-group access rules.
--
-- Four tables mirroring the asset access-rule machinery, kept 100% parallel
-- to the PAM session tables (assets / asset_groups / access_rules are NOT
-- touched by this migration):
--
--   vault_secrets        -- org-owned secrets; the value is a vauban-vault
--                           ciphertext envelope ("vN:...", domain "secrets").
--   secret_groups        -- groups of secrets (incl. the virtual singleton
--                           kind='all', mirror of the "All assets" group).
--   secret_secret_groups -- M:N membership junction.
--   secret_access_rules  -- vauban_groups (subject, read-only FK) to
--                           secret_groups (object). No protocols, no MFA,
--                           no JIT: the consumer is an M2M API key.
--
-- Deletion semantics: vault_secrets rows are hard-deleted (traceability
-- lives in the WORM audit log, not in tombstones).

-- ---------------------------------------------------------------------------
-- 1. Secrets
-- ---------------------------------------------------------------------------

CREATE TABLE vault_secrets (
    id SERIAL PRIMARY KEY,
    uuid UUID NOT NULL UNIQUE DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    -- Vault envelope "vN:base64(nonce||ct||tag)", domain "secrets".
    -- TEXT: encrypted+base64 payloads routinely exceed 255 chars.
    ciphertext TEXT NOT NULL,
    -- Incremented on every value rotation so M2M consumers can detect
    -- a rotation without downloading the value.
    version INTEGER NOT NULL DEFAULT 1,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_by_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    updated_by_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_vault_secrets_uuid ON vault_secrets(uuid);
CREATE INDEX idx_vault_secrets_active ON vault_secrets(is_active) WHERE is_active = true;

-- ---------------------------------------------------------------------------
-- 2. Secret groups (incl. virtual 'all' singleton)
-- ---------------------------------------------------------------------------

CREATE TABLE secret_groups (
    id SERIAL PRIMARY KEY,
    uuid UUID NOT NULL UNIQUE DEFAULT uuid_generate_v4(),
    name VARCHAR(100) NOT NULL UNIQUE,
    slug VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    kind VARCHAR(16) NOT NULL DEFAULT 'static',
    created_by_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    updated_by_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT secret_groups_kind_check CHECK (kind IN ('static', 'all'))
);

CREATE INDEX idx_secret_groups_uuid ON secret_groups(uuid);

-- At most one row may exist per non-'static' kind (singleton virtual group).
CREATE UNIQUE INDEX uniq_secret_groups_kind_singleton
    ON secret_groups (kind)
    WHERE kind <> 'static';

-- ---------------------------------------------------------------------------
-- 3. Membership junction
-- ---------------------------------------------------------------------------

CREATE TABLE secret_secret_groups (
    secret_id INTEGER NOT NULL REFERENCES vault_secrets(id) ON DELETE CASCADE,
    secret_group_id INTEGER NOT NULL REFERENCES secret_groups(id) ON DELETE CASCADE,
    PRIMARY KEY (secret_id, secret_group_id)
);

CREATE INDEX idx_secret_secret_groups_group ON secret_secret_groups(secret_group_id);

-- ---------------------------------------------------------------------------
-- 4. Access rules (subject: vauban_groups, object: secret_groups)
-- ---------------------------------------------------------------------------

CREATE TABLE secret_access_rules (
    id SERIAL PRIMARY KEY,
    uuid UUID NOT NULL UNIQUE DEFAULT uuid_generate_v4(),
    name VARCHAR(100) NOT NULL,
    description TEXT,
    user_group_id INTEGER NOT NULL REFERENCES vauban_groups(id) ON DELETE CASCADE,
    secret_group_id INTEGER NOT NULL REFERENCES secret_groups(id) ON DELETE CASCADE,
    valid_from TIMESTAMPTZ,
    valid_until TIMESTAMPTZ,
    is_active BOOLEAN NOT NULL DEFAULT true,
    priority INTEGER NOT NULL DEFAULT 0,
    created_by_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    updated_by_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_group_id, secret_group_id)
);

CREATE INDEX idx_secret_access_rules_uuid ON secret_access_rules(uuid);
CREATE INDEX idx_secret_access_rules_user_group ON secret_access_rules(user_group_id);
CREATE INDEX idx_secret_access_rules_secret_group ON secret_access_rules(secret_group_id);
CREATE INDEX idx_secret_access_rules_active ON secret_access_rules(is_active) WHERE is_active = true;

-- ---------------------------------------------------------------------------
-- 5. Virtual group defenses (mirror of block_*_on_virtual_groups for assets)
-- ---------------------------------------------------------------------------

-- Forbid any membership row that targets a virtual secret group. Triggered
-- BEFORE INSERT and BEFORE UPDATE so re-pointing an existing membership at
-- the virtual row is also caught.
CREATE OR REPLACE FUNCTION block_membership_on_virtual_secret_groups()
RETURNS TRIGGER AS $$
DECLARE
    target_kind VARCHAR(16);
BEGIN
    SELECT kind INTO target_kind
        FROM secret_groups
        WHERE id = NEW.secret_group_id;
    IF target_kind IS NOT NULL AND target_kind <> 'static' THEN
        RAISE EXCEPTION
            'cannot add members to virtual secret_group (id=%, kind=%)',
            NEW.secret_group_id, target_kind
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER block_membership_on_virtual_secret_groups_insert
    BEFORE INSERT ON secret_secret_groups
    FOR EACH ROW EXECUTE FUNCTION block_membership_on_virtual_secret_groups();

CREATE TRIGGER block_membership_on_virtual_secret_groups_update
    BEFORE UPDATE ON secret_secret_groups
    FOR EACH ROW EXECUTE FUNCTION block_membership_on_virtual_secret_groups();

-- Forbid any UPDATE/DELETE on a non-static secret_groups row (rename,
-- delete, and the kind flip-flop attack UPDATE SET kind='static').
CREATE OR REPLACE FUNCTION block_mutation_on_virtual_secret_groups()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.kind <> 'static' THEN
            RAISE EXCEPTION
                'cannot delete virtual secret_group (id=%, kind=%, uuid=%)',
                OLD.id, OLD.kind, OLD.uuid
                USING ERRCODE = 'check_violation';
        END IF;
        RETURN OLD;
    ELSIF TG_OP = 'UPDATE' THEN
        IF OLD.kind <> 'static' THEN
            RAISE EXCEPTION
                'cannot update virtual secret_group (id=%, kind=%, uuid=%)',
                OLD.id, OLD.kind, OLD.uuid
                USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER block_mutation_on_virtual_secret_groups_update
    BEFORE UPDATE ON secret_groups
    FOR EACH ROW EXECUTE FUNCTION block_mutation_on_virtual_secret_groups();

CREATE TRIGGER block_mutation_on_virtual_secret_groups_delete
    BEFORE DELETE ON secret_groups
    FOR EACH ROW EXECUTE FUNCTION block_mutation_on_virtual_secret_groups();

-- ---------------------------------------------------------------------------
-- 6. Seed the singleton virtual "All secrets" group
-- ---------------------------------------------------------------------------

-- Reserved UUID with the mnemonic suffix '5ec4e7a11' (= "secret all"). The
-- slug starts with '__' to flag the row as system-managed in ad-hoc queries.
-- Idempotent (ON CONFLICT DO NOTHING) so re-running the migration after a
-- partial restore acts as a self-heal; the explicit kind guard fails loud if
-- the reserved UUID exists with the wrong kind (the partial unique index
-- would not catch a kind='static' squatter).
DO $$
DECLARE
    reserved_uuid CONSTANT UUID := '00000000-0000-0000-0000-0005ec4e7a11';
    existing_kind VARCHAR(16);
BEGIN
    SELECT kind INTO existing_kind
        FROM secret_groups
        WHERE uuid = reserved_uuid;
    IF existing_kind IS NOT NULL AND existing_kind <> 'all' THEN
        RAISE EXCEPTION
            'reserved virtual secret_group UUID % already exists with kind=% (expected ''all'' or absent); refusing to migrate to avoid corrupting the singleton invariant',
            reserved_uuid, existing_kind;
    END IF;

    INSERT INTO secret_groups (uuid, name, slug, kind, description)
    VALUES (
        reserved_uuid,
        'All secrets',
        '__all-secrets__',
        'all',
        'System-managed virtual group: when referenced from a secret_access_rule, dynamically grants the rule over every active secret. Cannot be edited, deleted, or have secrets attached/detached.'
    )
    ON CONFLICT (uuid) DO NOTHING;
END $$;
