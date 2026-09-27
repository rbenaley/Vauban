//! TRUSTED R1 — contestation detail template.

use askama::Template;

use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};

#[derive(Debug, Clone)]
pub struct ContestationView {
    pub uuid: String,
    pub decision_id: String,
    pub session_uuid: String,
    pub status: String,
    pub status_label: String,
    pub subject_username: String,
    pub opened_by_username: String,
    pub opened_at: String,
    pub open_reason: String,
    pub claimed_by_username: Option<String>,
    pub claimed_at: Option<String>,
    pub resolved_by_username: Option<String>,
    pub resolved_at: Option<String>,
    pub resolution_note: Option<String>,
    pub restore_group_id: Option<i32>,
    pub restore_applied_at: Option<String>,
    pub can_claim: bool,
    pub can_resolve: bool,
    pub is_opener: bool,
    /// IAM suspension 1:1 — group that will be restored on overturn.
    pub can_overturn: bool,
    pub restore_group_name: Option<String>,
}

#[derive(Template)]
#[template(path = "sessions/contestation_detail.html")]
pub struct ContestationDetailTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<UserContext>,
    pub c: ContestationView,
    pub mcp_nav: String,
    pub mcp_can_supervise: bool,
}
