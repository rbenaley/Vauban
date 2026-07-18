-- Irreversible data cleanup: the purged rows were memberships of
-- soft-deleted accounts (dead data with no functional meaning), so
-- there is nothing to restore. Intentional no-op.
SELECT 1;
