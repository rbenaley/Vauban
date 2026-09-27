-- Per-access-rule IAM consequence after a first Mission Seal CheckStep deny.
-- Default matches today's product (RemoveGroupMember). terminate is opt-in.

ALTER TABLE access_rules
    ADD COLUMN IF NOT EXISTS mcp_drift_iam TEXT NOT NULL DEFAULT 'suspend_group';

ALTER TABLE access_rules
    DROP CONSTRAINT IF EXISTS access_rules_mcp_drift_iam_chk;

ALTER TABLE access_rules
    ADD CONSTRAINT access_rules_mcp_drift_iam_chk
    CHECK (mcp_drift_iam IN (
        'terminate',
        'suspend_group',
        'revoke_opener_key',
        'soft_delete_user'
    ));

COMMENT ON COLUMN access_rules.mcp_drift_iam IS
    'IAM after first Mission Seal drift. PEP/WORM/mail unchanged. Default suspend_group.';
