//! MCP HITL pending approvals list (Phase 4.3).

use askama::Template;

use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};

#[derive(Debug, Clone)]
pub struct McpHitlContractStep {
    pub step_id: String,
    pub operation: String,
    pub mode: String,
    pub intent: String,
    /// Compact JSON of Contract args after sensitive-field redaction.
    pub arguments_redacted: String,
}

#[derive(Debug, Clone, Default)]
pub struct McpHitlStory {
    pub summary: String,
    pub context: String,
    pub objective: String,
    pub risks: String,
}

#[derive(Debug, Clone)]
pub struct McpHitlListItem {
    pub session_id: String,
    pub pending_id: String,
    pub tool: String,
    pub args_blake3: String,
    pub expires_at: String,
    pub requester_user_id: String,
    pub requester_label: String,
    pub asset_name: String,
    pub is_own: bool,
    pub mandate_id: String,
    pub sealed_digest: String,
    pub story: Option<McpHitlStory>,
    pub contract_steps: Vec<McpHitlContractStep>,
}

#[derive(Template)]
#[template(path = "sessions/mcp_hitl_list.html")]
pub struct McpHitlListTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<UserContext>,
    pub pendings: Vec<McpHitlListItem>,
    pub own_pendings: Vec<McpHitlListItem>,
    pub mcp_nav: String,
    pub mcp_can_supervise: bool,
}
