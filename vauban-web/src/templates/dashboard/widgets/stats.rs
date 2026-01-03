/// VAUBAN Web - Stats widget template.

use askama::Template;

#[derive(Debug, Clone)]
pub struct StatsData {
    pub active_sessions: i32,
    pub today_sessions: i32,
    pub week_sessions: i32,
}

#[derive(Template)]
#[template(path = "dashboard/widgets/stats.html")]
pub struct StatsWidget {
    pub stats: StatsData,
}

