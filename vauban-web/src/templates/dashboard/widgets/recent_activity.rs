/// VAUBAN Web - Recent activity widget template.

use askama::Template;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct ActivityItem {
    pub user: String,
    pub action: String,
    pub asset: Option<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Template)]
#[template(path = "dashboard/widgets/recent_activity.html")]
pub struct RecentActivityWidget {
    pub activities: Vec<ActivityItem>,
}

