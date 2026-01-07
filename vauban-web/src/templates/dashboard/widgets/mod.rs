pub mod active_sessions;
pub mod assets_status;
pub mod recent_activity;
/// VAUBAN Web - Dashboard widget templates.
pub mod stats;

pub use active_sessions::{ActiveSessionItem, ActiveSessionsWidget};
pub use assets_status::AssetsStatusWidget;
pub use recent_activity::{ActivityItem, RecentActivityWidget};
pub use stats::{StatsData, StatsWidget};
