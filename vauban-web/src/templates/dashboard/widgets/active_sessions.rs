/// VAUBAN Web - Active sessions widget template.

use askama::Template;

#[derive(Debug, Clone)]
pub struct ActiveSessionItem {
    pub id: i32,
    pub asset_name: String,
    pub asset_hostname: String,
    pub session_type: String,
    pub duration_seconds: Option<i64>,
}

#[derive(Template)]
#[template(path = "dashboard/widgets/active_sessions.html")]
pub struct ActiveSessionsWidget {
    pub sessions: Vec<ActiveSessionItem>,
}

