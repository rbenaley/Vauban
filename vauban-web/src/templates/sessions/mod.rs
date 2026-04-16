pub mod active_list;
pub mod approval_detail;
pub mod approval_list;
pub mod my_requests;
pub mod recording_detail;
pub mod recording_list;
pub mod recording_play;
pub mod session_detail;
/// VAUBAN Web - Sessions templates.
pub mod session_list;
pub mod terminal;

/// Shared Tailwind badge classes for session/request statuses.
///
/// Single source of truth so that every page (`/sessions`, `/sessions/{id}`,
/// `/sessions/my-requests`, `/sessions/approvals`, ...) renders the same
/// colours for the same status.
pub fn session_status_class(status: &str) -> &'static str {
    match status {
        "pending" => "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/50 dark:text-yellow-300",
        "approved" => "bg-green-100 text-green-800 dark:bg-green-900/50 dark:text-green-300",
        "rejected" => "bg-red-100 text-red-800 dark:bg-red-900/50 dark:text-red-300",
        "expired" | "orphaned" => {
            "bg-gray-100 text-gray-800 dark:bg-gray-900/50 dark:text-gray-300"
        }
        "consumed" | "active" | "connecting" => {
            "bg-blue-100 text-blue-800 dark:bg-blue-900/50 dark:text-blue-300"
        }
        "disconnected" | "completed" => {
            "bg-indigo-100 text-indigo-800 dark:bg-indigo-900/50 dark:text-indigo-300"
        }
        "terminated" => {
            "bg-orange-100 text-orange-800 dark:bg-orange-900/50 dark:text-orange-300"
        }
        _ => "bg-gray-100 text-gray-800 dark:bg-gray-900/50 dark:text-gray-300",
    }
}

pub use active_list::{
    ActiveListContentWidget, ActiveListStatsWidget, ActiveListTemplate, ActiveSessionItem,
};
pub use approval_detail::ApprovalDetailTemplate;
pub use approval_list::ApprovalListTemplate;
pub use my_requests::MyRequestsTemplate;
pub use recording_list::RecordingListTemplate;
pub use session_detail::SessionDetailTemplate;
pub use session_list::{SessionListContentWidget, SessionListItem, SessionListTemplate};
pub use terminal::TerminalTemplate;

#[cfg(test)]
mod tests {
    use super::session_status_class;

    #[test]
    fn test_pending() {
        assert!(session_status_class("pending").contains("yellow"));
    }

    #[test]
    fn test_approved() {
        assert!(session_status_class("approved").contains("green"));
    }

    #[test]
    fn test_rejected() {
        assert!(session_status_class("rejected").contains("red"));
    }

    #[test]
    fn test_expired() {
        assert!(session_status_class("expired").contains("gray"));
    }

    #[test]
    fn test_orphaned() {
        assert!(session_status_class("orphaned").contains("gray"));
    }

    #[test]
    fn test_expired_and_orphaned_share_same_class() {
        assert_eq!(session_status_class("expired"), session_status_class("orphaned"));
    }

    #[test]
    fn test_consumed() {
        assert!(session_status_class("consumed").contains("blue"));
    }

    #[test]
    fn test_active() {
        assert!(session_status_class("active").contains("blue"));
    }

    #[test]
    fn test_connecting() {
        assert!(session_status_class("connecting").contains("blue"));
    }

    #[test]
    fn test_active_group_shares_same_class() {
        let cls = session_status_class("active");
        assert_eq!(cls, session_status_class("consumed"));
        assert_eq!(cls, session_status_class("connecting"));
    }

    #[test]
    fn test_disconnected() {
        assert!(session_status_class("disconnected").contains("indigo"));
    }

    #[test]
    fn test_completed() {
        assert!(session_status_class("completed").contains("indigo"));
    }

    #[test]
    fn test_disconnected_and_completed_share_same_class() {
        assert_eq!(
            session_status_class("disconnected"),
            session_status_class("completed")
        );
    }

    #[test]
    fn test_terminated() {
        assert!(session_status_class("terminated").contains("orange"));
    }

    #[test]
    fn test_unknown_falls_back_to_gray() {
        assert!(session_status_class("whatever").contains("gray"));
    }

    #[test]
    fn test_empty_falls_back_to_gray() {
        assert!(session_status_class("").contains("gray"));
    }

    #[test]
    fn test_all_statuses_return_nonempty_class() {
        let statuses = [
            "pending", "approved", "rejected", "expired", "orphaned",
            "consumed", "active", "connecting", "disconnected", "completed",
            "terminated", "unknown",
        ];
        for s in statuses {
            assert!(!session_status_class(s).is_empty(), "class for '{s}' must not be empty");
        }
    }
}
