pub mod active_list;
pub mod approval_detail;
pub mod approval_list;
pub mod recording_detail;
pub mod recording_list;
pub mod recording_play;
pub mod session_detail;
/// VAUBAN Web - Sessions templates.
pub mod session_list;
pub mod terminal;

pub use active_list::{
    ActiveListContentWidget, ActiveListStatsWidget, ActiveListTemplate, ActiveSessionItem,
};
pub use approval_detail::ApprovalDetailTemplate;
pub use approval_list::ApprovalListTemplate;
pub use recording_list::RecordingListTemplate;
pub use session_detail::SessionDetailTemplate;
pub use session_list::SessionListTemplate;
pub use terminal::TerminalTemplate;