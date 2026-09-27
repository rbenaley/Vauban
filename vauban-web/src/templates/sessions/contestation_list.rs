//! TRUSTED R1 — contestation list template.

use askama::Template;

use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};

#[derive(Debug, Clone)]
pub struct ContestationListItem {
    pub uuid: String,
    pub decision_id: String,
    pub session_uuid: String,
    pub status: String,
    pub status_label: String,
    pub subject_username: String,
    pub opened_by_username: String,
    pub opened_at: String,
    pub open_reason_preview: String,
    pub is_own_open: bool,
    pub is_open_queue: bool,
}

#[derive(Template)]
#[template(path = "sessions/contestation_list.html")]
pub struct ContestationListTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<UserContext>,
    pub items: Vec<ContestationListItem>,
    pub mcp_nav: String,
    pub mcp_can_supervise: bool,
}
