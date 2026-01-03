/// VAUBAN Web - Sessions templates.

pub mod session_list;
pub mod session_detail;
pub mod active_list;
pub mod approval_list;
pub mod approval_detail;
pub mod recording_list;
pub mod recording_detail;
pub mod recording_play;

pub use session_list::SessionListTemplate;
pub use session_detail::SessionDetailTemplate;
pub use active_list::ActiveListTemplate;
pub use approval_list::ApprovalListTemplate;
pub use approval_detail::ApprovalDetailTemplate;
pub use recording_list::RecordingListTemplate;
