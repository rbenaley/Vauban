-- Per-access-rule MCP tool whitelist (Lot 1a).
-- NULL  = no extra restriction from this rule (asset catalog still applies)
-- '{}'  = deny-all MCP tools for this rule
-- list  = only these tool names
-- Effective session whitelist = ∩(applicable rules) ∩ asset.connection_config.allowed_tools

ALTER TABLE access_rules
    ADD COLUMN IF NOT EXISTS mcp_allowed_tools TEXT[];

COMMENT ON COLUMN access_rules.mcp_allowed_tools IS
    'MCP tools granted by this rule. NULL = unrestricted (asset catalog); empty = deny-all; else allow-list. Intersected across applicable rules at session open.';
