ALTER TABLE access_rules DROP CONSTRAINT IF EXISTS access_rules_mcp_drift_iam_chk;
ALTER TABLE access_rules DROP COLUMN IF EXISTS mcp_drift_iam;
