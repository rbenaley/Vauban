//! Shared MCP tool checkbox option for access-rule forms.

/// One tool available for allow-listing / HITL-forcing on an access rule.
#[derive(Debug, Clone)]
pub struct McpToolOption {
    pub name: String,
    pub description: String,
    pub selected: bool,
    /// Checked in the rule's `mcp_hitl_tools` force-list.
    pub hitl_selected: bool,
}
