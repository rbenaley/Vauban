-- Per-access-rule MCP HITL force-list (Phase 4 / 09 §5.1).
-- NULL  = no extra HITL from this rule (catalogue hitl flags still apply)
-- list  = tool names forced to HITL (union with catalogue; never removes catalogue hitl)
-- Effective HITL = catalogue.hitl OR name ∈ ∪(applicable rules.mcp_hitl_tools)

ALTER TABLE access_rules
    ADD COLUMN IF NOT EXISTS mcp_hitl_tools TEXT[];

COMMENT ON COLUMN access_rules.mcp_hitl_tools IS
    'MCP tools forced to HITL by this rule. NULL = none; else unioned with catalogue hitl at session open (add-only).';
