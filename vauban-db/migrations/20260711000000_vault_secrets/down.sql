-- Disable triggers FIRST so the seed row can be removed.
DROP TRIGGER IF EXISTS block_mutation_on_virtual_secret_groups_delete ON secret_groups;
DROP TRIGGER IF EXISTS block_mutation_on_virtual_secret_groups_update ON secret_groups;
DROP TRIGGER IF EXISTS block_membership_on_virtual_secret_groups_update ON secret_secret_groups;
DROP TRIGGER IF EXISTS block_membership_on_virtual_secret_groups_insert ON secret_secret_groups;
DROP FUNCTION IF EXISTS block_mutation_on_virtual_secret_groups();
DROP FUNCTION IF EXISTS block_membership_on_virtual_secret_groups();

DROP TABLE IF EXISTS secret_access_rules;
DROP TABLE IF EXISTS secret_secret_groups;
DROP TABLE IF EXISTS secret_groups;
DROP TABLE IF EXISTS vault_secrets;
