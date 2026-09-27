-- Per-access-rule MCP Mission Seal force-list.
-- Policy SoT: require_plan is decided here (not the asset catalogue).
-- NULL = this rule does not require a plan
-- list = tool names that must carry Story+Contract (implies HITL at PEP)

ALTER TABLE access_rules
    ADD COLUMN IF NOT EXISTS mcp_require_plan_tools TEXT[];

COMMENT ON COLUMN access_rules.mcp_require_plan_tools IS
    'MCP tools that require Mission Seal (Story+Contract) by this rule. NULL = none.';
