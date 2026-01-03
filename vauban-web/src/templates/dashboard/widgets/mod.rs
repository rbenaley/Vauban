/// VAUBAN Web - Dashboard widget templates.

pub mod stats;
pub mod active_sessions;
pub mod assets_status;
pub mod recent_activity;

pub use stats::{StatsWidget, StatsData};
pub use active_sessions::{ActiveSessionsWidget, ActiveSessionItem};
pub use assets_status::AssetsStatusWidget;
pub use recent_activity::{RecentActivityWidget, ActivityItem};

