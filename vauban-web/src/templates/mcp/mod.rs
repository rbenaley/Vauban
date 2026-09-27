//! MCP zone templates (`/sessions/mcp`).

use askama::Template;

use crate::templates::assets::access_rule_create::GroupOption;
use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};

#[derive(Debug, Clone)]
pub struct McpMatrixTool {
    pub name: String,
    pub description: String,
    /// `off` | `allow` | `hitl` | `require_plan` — one value per tool.
    pub mode: String,
    /// Asset names that expose this tool (` · ` joined).
    pub asset_label: String,
    /// True when the same name is approved on more than one asset.
    pub shared: bool,
    pub descriptions_diverge: bool,
}

#[derive(Debug, Clone)]
pub struct McpMatrixSection {
    pub heading: String,
    /// Empty = no extra hint under the heading.
    pub hint: String,
    /// `MCP` (or empty when the heading is not a single asset).
    pub badge_label: String,
    pub tools: Vec<McpMatrixTool>,
}

#[derive(Debug, Clone)]
pub struct McpAccessRuleItem {
    pub uuid: String,
    pub name: String,
    pub user_group_name: String,
    pub asset_group_name: String,
    pub is_active: bool,
    pub tools_summary: String,
    pub mixed: bool,
}

#[derive(Debug, Clone)]
pub struct McpAccessRuleForm {
    pub name: String,
    pub description: String,
    pub user_group_id: String,
    pub asset_group_id: String,
    pub valid_from: String,
    pub valid_until: String,
    pub is_active: bool,
    pub priority: String,
    /// Product default `suspend_group` (see [`Default`]).
    pub mcp_drift_iam: String,
}

impl Default for McpAccessRuleForm {
    fn default() -> Self {
        Self {
            name: String::new(),
            description: String::new(),
            user_group_id: String::new(),
            asset_group_id: String::new(),
            valid_from: String::new(),
            valid_until: String::new(),
            is_active: false,
            priority: String::new(),
            mcp_drift_iam: shared::mcp_drift_iam::default_mcp_drift_iam(),
        }
    }
}

#[derive(Template)]
#[template(path = "mcp/access_list.html")]
pub struct McpAccessListTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<UserContext>,
    pub mcp_nav: String,
    pub mcp_can_supervise: bool,
    pub rules: Vec<McpAccessRuleItem>,
}

#[derive(Template)]
#[template(path = "mcp/access_create.html")]
pub struct McpAccessCreateTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<UserContext>,
    pub mcp_nav: String,
    pub mcp_can_supervise: bool,
    pub form: McpAccessRuleForm,
    pub user_groups: Vec<GroupOption>,
    pub asset_groups: Vec<GroupOption>,
    pub sections: Vec<McpMatrixSection>,
}

#[derive(Template)]
#[template(path = "mcp/access_edit.html")]
pub struct McpAccessEditTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<UserContext>,
    pub mcp_nav: String,
    pub mcp_can_supervise: bool,
    pub uuid: String,
    pub form: McpAccessRuleForm,
    pub user_groups: Vec<GroupOption>,
    pub asset_groups: Vec<GroupOption>,
    pub sections: Vec<McpMatrixSection>,
}

#[derive(Template)]
#[template(path = "mcp/access_detail.html")]
pub struct McpAccessDetailTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<UserContext>,
    pub mcp_nav: String,
    pub mcp_can_supervise: bool,
    pub uuid: String,
    pub name: String,
    pub description: Option<String>,
    pub user_group_name: String,
    pub asset_group_name: String,
    pub is_active: bool,
    pub priority: i32,
    pub valid_from: Option<String>,
    pub valid_until: Option<String>,
    pub mixed: bool,
    pub other_protocols_label: String,
    /// Same matrix as the edit form — modes from this access rule only.
    pub sections: Vec<McpMatrixSection>,
    pub mcp_drift_iam: String,
    pub mcp_drift_iam_label: String,
}
