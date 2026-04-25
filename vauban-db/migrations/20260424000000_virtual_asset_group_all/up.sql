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
